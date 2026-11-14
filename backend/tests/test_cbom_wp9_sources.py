"""CBOM Sources outputs (WP9): metadata edits never cancel jobs, internet exposure in the risk score, the run snapshot,
the Mosca merge, library end of life as of the run, the node-run export (deterministic serial, versions, XML).

Uses the same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import CERT_FACTS, PASSWORD, _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.utilities.cbom_sources import posture as P  # noqa: E402

PUBLIC_TLS = {"type": "tls_endpoint", "target": "1.1.1.1", "location": "1.1.1.1:443",
              "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA"]}}
PRIVATE_TLS = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
               "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA"]}}


def _post_assets(api, job, hdr, assets, batch="b1"):
    return api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
               json={"lease_id": job["lease_id"], "batch_id": batch, "assets": assets})


def _source(api, src_id):
    return api("GET", f"/1/cbom/sources/items/{src_id}").json()["source"]


# ------------------------------------------------------------------------------------------- metadata vs connection
def test_metadata_edits_keep_running_jobs_and_the_connection_test(api, world):
    engine, _ = world
    src, _run, claim, hdr = _collect_job(api, engine)
    job = claim["job"]
    cur = _source(api, src["id"])
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "name": "renamed-dc", "config": {**cur["config"], "business_criticality": "high", "exposure": "internet"},
        "expected_version": cur["row_version"]})
    assert r.status_code == 200, r.text
    after = r.json()["source"]
    assert after["row_version"] == cur["row_version"] + 1  # the edit version still moves (stale forms get a 409)
    assert after["config"]["exposure"] == "internet" and after["config"]["business_criticality"] == "high"
    ok = _post_assets(api, job, hdr, [PRIVATE_TLS])
    assert ok.status_code == 200, ok.text  # the claimed job is still valid
    # a connection change (where the source points) still stops it
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**after["config"], "targets": ["10.20.0.9"]}, "secrets": {"password": PASSWORD},
        "expected_version": after["row_version"]})
    assert r.status_code == 200, r.text
    stale = _post_assets(api, job, hdr, [PRIVATE_TLS], batch="b2")
    assert stale.status_code == 409 and "Source changed" in stale.text


def test_a_source_form_keeps_every_metadata_field_unless_it_names_it(api, world):
    engine, _ = world
    src, _run, _claim, _hdr = _collect_job(api, engine)
    cur = _source(api, src["id"])
    cur = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**cur["config"], "business_criticality": "critical", "exposure": "internal"},
        "expected_version": cur["row_version"]}).json()["source"]
    form = {k: v for k, v in cur["config"].items() if k not in ("business_criticality", "exposure")}
    kept = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": form, "expected_version": cur["row_version"]})
    assert kept.status_code == 200 and kept.json()["source"]["config"]["exposure"] == "internal"
    assert kept.json()["source"]["config"]["business_criticality"] == "critical"
    cur = kept.json()["source"]
    cleared = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**form, "exposure": None}, "expected_version": cur["row_version"]})
    assert cleared.status_code == 200 and cleared.json()["source"]["config"]["exposure"] is None
    bad = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**form, "exposure": "dmz"}, "expected_version": cleared.json()["source"]["row_version"]})
    assert bad.status_code == 400


# ------------------------------------------------------------------------------------------- exposure and snapshot
@pytest.mark.parametrize("facts,target,override,segment,expected", [
    ({}, "1.1.1.1", None, None, ("internet", "public IP address 1.1.1.1")),
    ({}, "10.1.2.3:443", None, None, ("internal", "private IP address 10.1.2.3")),
    ({}, "[2606:4700:4700::1111]:443", None, None, ("internet", "public IP address 2606:4700:4700::1111")),
    ({}, "[fd00::5]:443", None, None, ("internal", "private IP address fd00::5")),
    ({}, "app.bank.local", None, None, ("unknown", "no exposure fact")),
    ({}, "10.1.2.3", None, "DMZ", ("internet", "scan node segment DMZ")),
    ({"internet_facing": True, "internet_facing_reason": "load balancer scheme internet-facing"}, "aws", None, None,
     ("internet", "reported by the collector: load balancer scheme internet-facing")),
    ({"internet_facing": False}, "1.1.1.1", None, None, ("internal", "reported by the collector")),
    ({"internet_facing": True}, "1.1.1.1", "internal", None, ("internal", "set on the source")),
    ({}, "10.1.2.3", "unknown", "DMZ", ("unknown", "set on the source")),
])
def test_exposure_rules_first_match_wins(facts, target, override, segment, expected):
    assert P.asset_exposure(facts, target, None, override=override, node_segment=segment) == expected


def test_exposure_factor_is_documented_and_never_lowers_a_risk():
    assert P.EXPOSURE_FACTOR == {"internet": 1.5, "internal": 1.0, "unknown": 1.0}


def test_internet_exposure_raises_the_risk_and_the_run_keeps_its_snapshot(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    assert _post_assets(api, claim["job"], hdr, [PUBLIC_TLS, PRIVATE_TLS]).status_code == 200
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    by_loc = {r["location"]: r for r in out["top_risks"]}
    pub, priv = by_loc["1.1.1.1:443"], by_loc["10.20.0.1:443"]
    assert (pub["exposure"], priv["exposure"]) == ("internet", "internal")
    assert pub["score"] == round(priv["score"] * 1.5, 1) and out["top_risks"][0]["location"] == "1.1.1.1:443"
    assert out["exposure"] == {"internet": 1, "internal": 1, "unknown": 0}
    # editing the source after the run does not re-score the run (criticality and exposure were snapshotted)
    cur = _source(api, src["id"])
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**cur["config"], "business_criticality": "critical", "exposure": "internal"},
        "expected_version": cur["row_version"]})
    assert r.status_code == 200
    again = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    assert again["top_risks"] == out["top_risks"]
    asset_id = pub["id"]
    detail = api("GET", f"/1/cbom/sources/assets/{asset_id}").json()["asset"]
    assert (detail["exposure"], detail["criticality"], detail["exposure_factor"]) == ("internet", "medium", 1.5)


def test_a_job_without_a_snapshot_reads_the_current_source():
    class _Src:
        config = {"business_criticality": "high", "exposure": "internet", "data_lifetime_years": 7}

    class _Node:
        segment = "DMZ"

    assert P.job_metadata({}, _Src(), _Node()) == {"criticality": "high", "exposure": "internet", "segment": "DMZ",
                                                   "data_lifetime_years": 7}
    snap = {"metadata": {"business_criticality": "low", "exposure": None, "node_segment": "Core",
                         "data_lifetime_years": 0}}
    assert P.job_metadata(snap, _Src(), _Node()) == {"criticality": "low", "exposure": None, "segment": "Core",
                                                     "data_lifetime_years": 0}  # CB-19: the source's Mosca X


# ------------------------------------------------------------------------------------------- Mosca merge
def test_mosca_merge_keeps_unsent_fields_and_null_clears(api, world):
    full = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
    assert api("PATCH", "/1/cbom/sources/settings", json={"risk_model": full}).status_code == 200
    one = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"threat_years": 20}})
    assert one.status_code == 200
    assert one.json()["settings"]["risk_model"] == {**full, "threat_years": 20}
    cleared = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"migration_years": None}})
    assert cleared.json()["settings"]["risk_model"] == {**full, "threat_years": 20, "migration_years": None}
    gone = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": None})
    assert gone.status_code == 200
    assert not any((gone.json()["settings"]["risk_model"] or {}).values())  # risk_model: null clears all three


def test_mosca_values_are_whole_years_from_0_to_100_and_a_refused_update_changes_nothing(api, world):
    full = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
    assert api("PATCH", "/1/cbom/sources/settings", json={"risk_model": full}).status_code == 200
    for bad in (True, 7.5, 7.0, "7", -1, 101, [7], {"years": 7}):
        r = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"migration_years": bad}})
        assert r.status_code in (400, 422), (bad, r.status_code)
    for bad_body in ({"threat_yrs": 9}, [1, 2, 3], "10,5,12"):
        assert api("PATCH", "/1/cbom/sources/settings", json={"risk_model": bad_body}).status_code in (400, 422), bad_body
    edges = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"data_shelf_life_years": 0, "threat_years": 100}})
    assert edges.status_code == 200
    assert edges.json()["settings"]["risk_model"] == {"data_shelf_life_years": 0, "migration_years": 5, "threat_years": 100}
    assert api("GET", "/1/cbom/sources/settings").json()["settings"]["risk_model"] == edges.json()["settings"]["risk_model"]


# ------------------------------------------------------------------------------------------- library end of life
def test_library_end_of_life_is_as_of_the_run_and_today_when_it_differs(api, world):
    from sqlmodel import Session

    from backend.new_models import CbomCollectedAsset

    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    lib = {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
           "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}}
    assert _post_assets(api, claim["job"], hdr, [lib]).status_code == 200
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]
    asset_id = items[0]["id"]
    with Session(engine) as s:  # the run happened before the 3.0 branch's end of life (2026-09-07)
        row = s.get(CbomCollectedAsset, asset_id)
        row.created_at = dt.datetime(2026, 1, 15)
        s.add(row)
        s.commit()
    detail = api("GET", f"/1/cbom/sources/assets/{asset_id}").json()["asset"]["library"]
    assert detail["eol_as_of"] == "2026-01-15" and detail["eol"]["passed"] is False
    assert detail["eol_today"]["passed"] is True and detail["eol_today"]["date"] == detail["eol"]["date"]


def test_a_library_that_reached_end_of_life_after_the_run_is_a_finding_in_every_view(api, world):
    """One rule: a date-based finding (library end of life, certificate expiry) is judged TODAY wherever a run's
    findings are shown - the list, its impact chips and filters, the posture totals, the heat map, the remediation
    waves, the asset panel and the CycloneDX JSON/XML - with the run's own verdict kept beside it; the stored row
    (the history drift and OSCAL compare) is never rewritten."""
    from sqlmodel import Session

    from backend.new_models import CbomCollectedAsset
    from backend.utilities.cbom_sources import crypto_kb
    from backend.utilities.cbom_sources.inventory import export_serial
    from backend.utilities.cbom_sources.posture import PQC_CLASS_MODEL

    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    lib = {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
           "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}}
    assert _post_assets(api, claim["job"], hdr, [lib, PRIVATE_TLS]).status_code == 200
    base = f"/1/cbom/sources/runs/{run['id']}"
    lib_id = next(i["id"] for i in api("GET", f"{base}/assets").json()["items"] if i["type"] == "crypto_library")
    with Session(engine) as s:  # the run happened before the 3.0 branch's end of life (2026-09-07): its record
        from backend.utilities.cbom_sources.classify import classify

        row = s.get(CbomCollectedAsset, lib_id)
        row.created_at = dt.datetime(2026, 1, 15)
        then = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts, row.created_at)
        row.impact, row.finding_codes, row.finding = then["impact"], then["finding_codes"], then["finding"]
        s.add(row)
        s.commit()
        run_impact, run_codes = row.impact, list(row.finding_codes or [])
    assert "LIB_EOL" not in run_codes and run_impact != "Medium"  # what the run itself recorded

    listing = api("GET", f"{base}/assets").json()
    item = next(i for i in listing["items"] if i["id"] == lib_id)
    assert "LIB_EOL" in item["finding_codes"] and item["impact"] == "Medium" and "end of life" in item["finding"]
    assert item["as_of_run"] == {"date": "2026-01-15", "judged_on": dt.datetime.utcnow().date().isoformat(),
                                 "impact": run_impact, "finding_codes": run_codes, "finding": item["as_of_run"]["finding"]}
    assert listing["facets"]["impact"].get("Medium", 0) >= 1
    assert lib_id in [i["id"] for i in api("GET", f"{base}/assets?impact=Medium").json()["items"]]
    if run_impact:
        assert lib_id not in [i["id"] for i in api("GET", f"{base}/assets?impact={run_impact}").json()["items"]]
    assert [i["id"] for i in api("GET", f"{base}/assets?q=reached%20end%20of%20life").json()["items"]] == [lib_id]

    posture = api("GET", f"{base}/posture").json()["posture"]
    assert "LIB_EOL" in {c["code"] for c in posture["top_codes"]}
    assert any(r["id"] == lib_id and r["impact"] == "Medium" for r in posture["top_risks"])

    heat = api("GET", f"{base}/heatmap?by=type").json()
    assert any(c["column"] == "crypto_library" and c["by_impact"]["Medium"] == 1 for c in heat["cells"])
    waves = api("GET", f"{base}/remediation").json()["items"]
    assert any(w["asset_id"] == lib_id and w["impact"] == "Medium" and "LIB_EOL" in w["finding_codes"] for w in waves)

    detail = api("GET", f"/1/cbom/sources/assets/{lib_id}").json()["asset"]
    assert detail["impact"] == "Medium" and "LIB_EOL" in [d["code"] for d in detail["details"]]
    assert detail["as_of_run"]["date"] == "2026-01-15" and detail["library"]["eol_today"]["passed"] is True

    bom = api("GET", f"{base}/cbom").json()
    comp = next(c for c in bom["components"] if c["bom-ref"] == f"zs-asset-{lib_id}")
    props = [(p["name"], p["value"]) for p in comp["properties"]]
    assert ("zs:finding_code", "LIB_EOL") in props and ("zs:impact", "Medium") in props
    assert ("zs:run_impact", run_impact or "Info") in props and ("zs:judged_on", item["as_of_run"]["judged_on"]) in props
    assert "ZS-CBOM-LIB_EOL" in {v["id"] for v in bom["vulnerabilities"]}
    assert bom["serialNumber"] != export_serial(run["id"], crypto_kb.version(),  # not the run's own record
                                                class_model=PQC_CLASS_MODEL)
    xml = api("GET", f"{base}/cbom?format=xml")
    assert xml.status_code == 200 and "LIB_EOL" in xml.text

    with Session(engine) as s:  # the history is kept: the stored verdict is the run's
        row = s.get(CbomCollectedAsset, lib_id)
        assert (row.impact, list(row.finding_codes or [])) == (run_impact, run_codes)


def test_certificate_expiry_follows_the_same_rule():
    from backend.utilities.cbom_sources.classify import verdict_today

    run, now = dt.datetime(2026, 1, 15), dt.datetime(2026, 11, 10)
    cert = {"not_after": "2026-03-01T00:00:00Z", "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": 2048}
    today = verdict_today("certificate", "RSA", 2048, None, cert, run, now)  # valid at the run, expired since
    assert "CERT_EXPIRED" in today["finding_codes"] and today["impact"] == "High"
    soon = verdict_today("certificate", "RSA", 2048, None, {**cert, "not_after": "2026-11-25T00:00:00Z"}, run, now)
    assert "CERT_EXPIRES_30D" in soon["finding_codes"]
    far = {**cert, "not_after": "2030-01-01T00:00:00Z"}
    assert verdict_today("certificate", "RSA", 2048, None, far, run, now) is None  # nothing date-based changed
    assert verdict_today("tls_endpoint", None, None, None, {"protocols": ["TLSv1.2"]}, run, now) is None
    assert verdict_today("certificate", "RSA", 2048, None, {**cert, "trust_store": True}, run, now) is None


def test_a_library_collected_after_its_end_of_life_shows_no_second_verdict(api, world):
    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    lib = {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
           "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}}
    assert _post_assets(api, claim["job"], hdr, [lib]).status_code == 200
    item = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"][0]
    assert "LIB_EOL" in item["finding_codes"] and item["as_of_run"] is None  # the run already found it


# ------------------------------------------------------------------------------------------- node-run export
def test_run_records_versions_and_the_export_serial_is_deterministic(api, world):
    from backend.utilities.cbom_sources import crypto_kb
    from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION
    from backend.utilities.cbom_sources.inventory import export_serial
    from backend.utilities.cbom_sources.posture import PQC_CLASS_MODEL

    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    assert _post_assets(api, claim["job"], hdr, [PRIVATE_TLS]).status_code == 200
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert detail["versions"]["kb"] == crypto_kb.version()
    assert detail["versions"]["classifier"] == CLASSIFIER_VERSION and CLASSIFIER_VERSION.startswith("rules-")
    assert detail["versions"]["engine"]
    first = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    second = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    # CB-18 ST-A: the class model is part of the serial (a release that changes the classes gives a new BOM)
    assert first["serialNumber"] == second["serialNumber"] == export_serial(run["id"], crypto_kb.version(),
                                                                            class_model=PQC_CLASS_MODEL)
    assert export_serial(run["id"], "2099.1.1.1", class_model=PQC_CLASS_MODEL) != first["serialNumber"]  # new KB
    assert export_serial(run["id"], crypto_kb.version(), class_model="pc-1") != first["serialNumber"]
    props = {p["name"]: p["value"] for p in first["metadata"]["properties"]}
    assert props["zs:run_kb_version"] == crypto_kb.version() and props["zs:classifier_version"] == CLASSIFIER_VERSION


def test_run_export_as_xml_is_valid_and_matches_the_json(api, world):
    from lxml import etree

    from backend.utilities.cbom_sources.cdx_xml import NS, validate_xml

    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    cert = {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay\x07<cert>",
            "algorithm": "RSA", "key_size": 1024, "facts": CERT_FACTS}
    assert _post_assets(api, claim["job"], hdr, [PRIVATE_TLS, cert]).status_code == 200
    as_json = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.cyclonedx+xml")
    assert "x-zs-signature-scope" not in r.headers  # a run's CBOM is not signed (CB-06); code-scan BOMs keep it
    assert r.headers["content-disposition"].endswith('.cdx.xml"')
    assert validate_xml(r.content) == []
    doc = etree.fromstring(r.content)
    ns = {"c": NS}
    assert doc.get("serialNumber") == as_json["serialNumber"]
    refs = [c.get("bom-ref") for c in doc.findall("c:components/c:component", ns)]
    assert refs == [c["bom-ref"] for c in as_json["components"]]
    vulns = [v.findtext("c:id", namespaces=ns) for v in doc.findall("c:vulnerabilities/c:vulnerability", ns)]
    assert vulns == [v["id"] for v in as_json["vulnerabilities"]]
    names = [c.findtext("c:name", namespaces=ns) for c in doc.findall("c:components/c:component", ns)]
    assert any(n and "<cert>" in n and "\x07" not in n for n in names)  # escaped, control character removed
    assert api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=pdf").status_code in (400, 422)
