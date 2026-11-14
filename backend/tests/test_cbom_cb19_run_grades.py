"""CB-19 PR-1: quantum risk grades (qg-1) on the run API, SQLite + the real routers.

Runs are seeded straight into the tables (sources, one collect job each with its metadata snapshot, classified asset
rows, coverage rows, job targets, the planner's skipped list), then read through the list, the asset detail, the run
posture and the grade-model route. PLAN §4 PR-1 plus the cx1-cx4 changes that fall inside PR-1.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb19_run_grades.py -q
"""
from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import sys
from collections import Counter
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _base  # noqa: E402  (shared fixtures: SQLite world + real routers)

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
)
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

NOW = dt.datetime(2026, 11, 14, 9, 0)
_RUN_IDS = itertools.count(1)
world = _base.world
api = _base.api
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
CA = {"is_ca": True, "key_alg": "RSA", "key_size": 2048, "not_after": "2034-01-01T00:00:00Z", "subject": "CN=Corp CA",
      "issuer": "CN=Corp CA", "sig_alg": "sha256WithRSAEncryption", "self_signed": True, "fingerprint_sha256": "cd" * 32}
QV_TLS = {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}
HYBRID_ONLY = {"protocols": ["TLSv1.3"], "pq_hybrid": True, "pq_group": "X25519MLKEM768"}  # CB-18: a named group


def _asset(type_, location, target="10.20.0.1", facts=None, algorithm=None, key_size=None, name=None):
    return {"type": type_, "location": location, "target": target, "facts": facts or {}, "algorithm": algorithm,
            "key_size": key_size, "name": name}


def _cov(target, check, status, detail="", **extra):
    return _asset("coverage", f"{target}#{check}" if target else check, target or None,
                  {"check": check, "status": status, "detail": detail, **extra}, name=check)


def seed(engine, *, mosca=MOSCA, sources=(), skipped=(), idle=(), include=None) -> dict:
    """One run. ``sources``: dicts with name, kind, config, metadata (the job's snapshot), status, outcome, result,
    assets; ``idle``: sources the run has no job or skipped entry for (left out by ``include`` or not chosen);
    ``include``: the run's group choice. Returns {"run": id, name: {"source": id, "uid": uid, "job": id,
    "assets": {location: id}}}."""
    out: dict = {}
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        settings.risk_model = dict(mosca or {})
        s.add(settings)
        s.commit()
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"cb19-{next(_RUN_IDS)}",
                                status="finished", created_at=NOW, breakdown={"groups": {}, "skipped": []},
                                include=include or {})
        s.add(run)
        s.commit()
        s.refresh(run)
        out["run"] = run.id
        skipped_rows = []
        for spec in list(sources) + list(skipped) + list(idle):
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=spec.get("kind", "linux_servers"),
                                       name=spec["name"], name_lower=spec["name"].lower(), config=spec.get("config") or {},
                                       enabled=spec.get("enabled", True))
            s.add(src)
            s.commit()
            s.refresh(src)
            entry = out[spec["name"]] = {"source": src.id, "uid": src.source_uid, "assets": {}}
            if spec in idle:
                continue
            if spec in skipped:
                skipped_rows.append({"source_id": src.id, "name": src.name, "kind": src.kind, "status": "skipped",
                                     "reason": spec["reason"]})
                continue
            meta = {"business_criticality": None, "exposure": None, "data_lifetime_years": None, "node_segment": None,
                    **(spec.get("metadata") or {})}
            uid = spec.get("uid", src.source_uid)
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect",
                                    status=spec.get("status", "success"), outcome=spec.get("outcome", "ok"),
                                    attempts=1, result=spec.get("result") or {}, error=spec.get("error"),
                                    params={"source_name": src.name, "source_uid": uid, "metadata": meta})
            s.add(job)
            s.commit()
            s.refresh(job)
            entry["job"] = job.id
            for i, a in enumerate(spec.get("assets") or []):
                v = classify(a["type"], a["algorithm"], a["key_size"], None, a["facts"], NOW)
                row = CbomCollectedAsset(
                    team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                    asset_key=hashlib.sha256(f"{i}|{a['location']}".encode()).hexdigest(), asset_type=a["type"],
                    cdx_type=v["cdx_type"], target=a["target"], location=a["location"], name=a["name"],
                    algorithm=a["algorithm"], key_size=a["key_size"], quantum_vulnerable=v["quantum_vulnerable"],
                    impact=v["impact"], finding_codes=v["finding_codes"], finding=v["finding"], facts=a["facts"],
                    created_at=NOW)
                s.add(row)
                s.commit()
                s.refresh(row)
                entry["assets"][a["location"]] = row.id
        run.breakdown = {"groups": {}, "skipped": skipped_rows}
        s.add(run)
        s.commit()
    return out


def items(api, run_id) -> dict[int, dict]:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["grade_model_version"].startswith("qg-1+") and body["grade_inputs"]["digest"]
    return {it["id"]: it for it in body["items"]}


def detail(api, asset_id) -> dict:
    r = api("GET", f"/1/cbom/sources/assets/{asset_id}")
    assert r.status_code == 200, r.text
    return r.json()["asset"]


def posture(api, run_id) -> dict:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/posture")
    assert r.status_code == 200, r.text
    return r.json()["posture"]


def one(api, engine, asset, *, mosca=MOSCA, metadata=None, kind="linux_servers") -> dict:
    w = seed(engine, mosca=mosca, sources=[{"name": "S-one", "kind": kind, "metadata": metadata, "assets": [asset]}])
    aid = w["S-one"]["assets"][asset["location"]]
    d = detail(api, aid)
    listed = items(api, w["run"])[aid]
    for key in ("q_grade", "q_label", "q_reason", "q_item_key"):
        assert listed[key] == d[key], key  # one value per asset on every surface
    return d


def g(d) -> tuple:
    return d["q_grade"], d["q_reason"]


# ----------------------------------------------------------------------------- DA rows and boundaries (PLAN §4)
def test_da1_internet_rsa_key_exchange_through_the_source_override(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS), metadata={"exposure": "internet"})
    assert g(d) == ("Q1", "qv_exceeds_internet") and d["q_label"] == "Critical"
    e = d["q_explain"]
    assert (e["class"], e["exposure"], e["x"], e["y"], e["z"]) == ("quantum-vulnerable", "internet", 10, 5, 12)
    assert e["inequality"] == "10 + 5 > 12" and e["exposure_basis"] == "set on the source"


def test_da1_internet_through_a_global_ip_target(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "52.95.110.1:443", target="52.95.110.1", facts=QV_TLS))
    assert g(d) == ("Q1", "qv_exceeds_internet") and d["q_explain"]["exposure_basis"].startswith("public IP")


def test_da2_internal(api, world):
    assert g(one(api, world[0], _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS))) == ("Q2", "qv_exceeds")


def test_da3_hybrid_endpoint_with_no_classical_exchange(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "10.20.0.2:443", target="10.20.0.2", facts=HYBRID_ONLY))
    assert g(d) == ("Q4", "pq_observed") and d["q_label"] == "Low"
    assert d["q_explain"]["fallback"] is False


def test_hybrid_is_graded_on_the_weakest_configuration_it_accepts(api, world):
    # HF-1 H1: a hybrid group plus TLS 1.2 RSA key transport; owner default: grade on the classical fallback
    facts = {"versions": {"TLSv1.2": True, "TLSv1.3": True}, "pq_hybrid": True, "pq_group": "X25519MLKEM768",
             "weak_ciphers_accepted": {"static_rsa": True, "cbc": True}}
    d = one(api, world[0], _asset("tls_endpoint", "52.95.110.1:443", target="52.95.110.1", facts=facts))
    # its own reason (review B / cx2 HF-1): "PQ deployed, classical fallback still accepted" is fixed differently
    assert g(d) == ("Q1", "qv_fallback_exceeds_internet")
    e = d["q_explain"]
    assert (e["class"], e["graded_class"], e["fallback"]) == ("hybrid", "quantum-vulnerable", True)
    assert "TLS 1.2" in e["fallback_basis"] or "static RSA" in e["fallback_basis"]


def test_ssh_with_a_pq_and_a_classical_kex_is_graded_on_the_classical_one(api, world):
    d = one(api, world[0], _asset("ssh_endpoint", "10.20.0.1:22", facts={"kex": ["mlkem768x25519-sha256",
                                                                                "curve25519-sha256"]}))
    # CB-18: an SSH hybrid key exchange with an identified ML-KEM component is "hybrid" (it was "quantum-safe")
    assert g(d) == ("Q2", "qv_fallback_exceeds") and d["q_explain"]["class"] == "hybrid"


def test_da4_mosca_unset(api, world):
    w = seed(world[0], mosca={}, sources=[{"name": "S", "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS),
                                                                  _asset("certificate", "/etc/ssl/ca.pem", facts=CA)]}])
    aid = w["S"]["assets"]["10.20.0.1:443"]
    d = detail(api, aid)
    assert g(d) == ("Q0", "mosca_missing") and d["q_item_key"] == "inputs:mosca"
    assert d["q_explain"]["missing"] == ["x", "y", "z"]
    p = posture(api, w["run"])
    assert p["q_grades"]["Q0"] == 2
    mosca_items = [i for i in p["q0_items"] if i["reason"] == "mosca_missing"]
    # FP-5: one missing team setting is ONE item with the count of affected assets, not one item per asset
    assert len(mosca_items) == 1 and mosca_items[0]["key"] == "inputs:mosca" and mosca_items[0]["count"] == 2
    assert mosca_items[0]["missing"] == ["x", "y", "z"] and p["q0_reasons"]["mosca_missing"] == 1


def test_boundary_x_plus_y_equals_z_is_within(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS), mosca={**MOSCA, "threat_years": 15})
    assert g(d) == ("Q3", "qv_within") and d["q_explain"]["inequality"] == "10 + 5 <= 15"


def test_source_x_zero_is_a_value(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS),
            mosca={"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 4},
            metadata={"data_lifetime_years": 0})
    assert g(d) == ("Q2", "qv_exceeds")
    assert (d["q_explain"]["x"], d["q_explain"]["x_basis"]) == (0, "source")


def test_source_x_unset_falls_back_to_the_team(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS))
    assert (d["q_explain"]["x"], d["q_explain"]["x_basis"]) == (10, "team")


@pytest.mark.parametrize("type_,facts,algorithm,basis", [
    ("certificate", CA, "RSA", "is_ca"),
    ("cloud_ca", {"key_alg": "RSA_2048"}, "RSA_2048", "cloud_ca"),
    ("ca_authority", {}, "RSA", "ca_authority"),
])
def test_trust_anchors_internal_exceeding(api, world, type_, facts, algorithm, basis):
    d = one(api, world[0], _asset(type_, "ca://corp", facts=facts, algorithm=algorithm, key_size=2048))
    assert g(d) == ("Q1", "qv_exceeds_anchor")
    assert (d["q_explain"]["anchor"], d["q_explain"]["anchor_basis"]) == (True, basis)


def test_idp_signing_key_is_not_an_anchor(api, world):
    d = one(api, world[0], _asset("signing_key", "idp://corp/k1", facts={"source": "idp", "kid": "k1"},
                                  algorithm="RSA", key_size=2048))
    assert g(d) == ("Q2", "qv_exceeds") and d["q_explain"]["anchor"] is False


def test_exposure_unknown_host_name(api, world):
    d = one(api, world[0], _asset("tls_endpoint", "pay.bank.example:443", target="pay.bank.example", facts=QV_TLS))
    # cx4 OB19-6: same grade as internal, its own reason code, so the list and the export can tell them apart
    assert g(d) == ("Q2", "qv_exceeds_exposure_unknown") and d["q_explain"]["exposure"] == "unknown"


def test_collector_internet_facing_beats_a_team_internal_override(api, world):
    facts = {**QV_TLS, "internet_facing": True, "internet_facing_reason": "load balancer scheme internet-facing"}
    d = one(api, world[0], _asset("load_balancer_tls", "arn:aws:elasticloadbalancing:x:1:listener/app/a/b/c",
                                  target="aws", facts=facts), metadata={"exposure": "internal"}, kind="aws_account")
    assert g(d) == ("Q1", "qv_exceeds_internet")
    assert "collector" in d["q_explain"]["exposure_basis"] and "internal" in d["q_explain"]["exposure_basis"]
    # the posture loop hands the score's exposure to the grade, except in exactly this case (review A)
    for override in ("internal", "unknown"):
        w = seed(world[0], sources=[{"name": f"S-{override}", "kind": "aws_account", "metadata": {"exposure": override},
                                     "assets": [_asset("load_balancer_tls", "arn:lb", target="aws", facts=facts)]}])
        p = posture(api, w["run"])
        assert p["q_grades"]["Q1"] == 1, override
        assert p["exposure"]["internet"] == 0  # the score keeps the source's setting


def test_grover_weakened_volume(api, world):
    facts = {"source": "bitlocker", "status": "FullyEncrypted", "method": "XtsAes128", "protection": "On", "mount": "C:"}
    d = one(api, world[0], _asset("disk_encryption", "C:", facts=facts, algorithm="XtsAes128"))
    assert g(d) == ("Q3", "grover_weakened")


def test_not_applicable_has_no_grade(api, world):
    d = one(api, world[0], _asset("database_config", "10.20.0.1:5432", facts={"password_encryption": "scram-sha-256"}))
    assert g(d) == (None, "not_applicable") and d["q_label"] is None and d["q_item_key"] is None


def test_unknown_oid_certificate_is_q0_unknown_verdict(api, world):
    facts = {"key_alg": "1.2.3.4.5.6.7", "not_after": "2030-01-01T00:00:00Z", "subject": "CN=x", "issuer": "CN=y"}
    d = one(api, world[0], _asset("certificate", "/etc/ssl/odd.pem", facts=facts))
    assert g(d) == ("Q0", "unknown_verdict")


# ----------------------------------------------------------------------------- unread scope items
def _scope_run(engine, *, timeouts=3):
    net_targets = [{"target": f"10.231.0.{i}", "status": "ok"} for i in range(16, 25)]
    net_targets += [{"target": f"10.231.1.{i}", "status": "timeout"} for i in range(timeouts)]
    net_targets += [{"target": "10.231.0.33", "status": "skipped_never_scan"}]
    return seed(engine, sources=[
        {"name": "S-host", "assets": [
            _asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS),
            _cov("10.20.0.1", "key and certificate files", "not_supported",
                 "Tier 1 does not search for key and certificate files; use Tier 2"),
            _cov("10.20.0.1", "BitLocker", "not_supported", "BitLocker is not installed on this server"),
            _cov("10.20.0.1", "linkerd policy", "not_installed"),
            _cov("10.20.0.2", "BitLocker", "denied", "Get-BitLockerVolume needs administrator rights"),
            _cov("10.20.0.1", "package list", "error", "neither dpkg-query nor rpm answered"),
        ], "result": {"targets": [{"target": "10.20.0.1", "status": "ok"}, {"target": "10.20.0.9", "status": "auth_failed"}]}},
        {"name": "R-net", "kind": "network_range", "assets": [
            _cov(f"10.231.0.{i}", "no answer", "unreachable", f"10.231.0.{i} did not answer on any listed port (443)")
            for i in (25, 27, 28, 29, 30)
        ] + [_cov(f"10.231.0.{i}", "ports not answering", "timeout", "ports 443, 8443 timed out") for i in (17, 18)]
          + [_asset("tls_endpoint", "10.231.0.16:443", target="10.231.0.16", facts=QV_TLS)],
         "result": {"targets": net_targets}},
        {"name": "S-fail", "status": "failure", "outcome": "failed", "error": "node lost the job"},
        {"name": "S-wait", "status": "pending", "outcome": None},
        {"name": "S-ca", "kind": "ca_connector", "result": {"targets": [
            {"target": "ca01", "status": "not_supported",
             "error": "no Active Directory Certificate Services CA is configured on this server"}]}},
        {"name": "S-trunc", "result": {"truncated": True, "counts": {"total": 1, "ok": 1}},
         "assets": [_asset("tls_endpoint", "10.20.0.7:443", target="10.20.0.7", facts=QV_TLS)]},
        {"name": "S-lost", "outcome": "partial", "result": {"asset_mismatch": {"reported": 9, "stored": 4}}},
        {"name": "K-img", "kind": "container_images", "result": {"targets": [
            {"target": "reg.example/app:1", "status": "not_supported",
             "error": "a layer is zstd-compressed (not read: no decompressor in the scan node)"},
            {"target": "reg.example/ok:2", "status": "ok"}]},
         "assets": [_cov("reg.example/ok:2", "Lambda env", "partial", "option off", by_choice=True),
                    _cov("reg.example/ok:2", "Batch env", "partial", "option off", by_choice=True)]},
        {"name": "C-aws", "kind": "aws_account", "result": {"targets": [
            {"target": "111122223333/eu-south-2", "status": "not_supported", "error": "kms: not_enabled",
             "services": {"kms": "not_enabled", "acm": "not_enabled"}},
            {"target": "111122223333/eu-west-1", "status": "ok"}]}},
    ], skipped=[{"name": "S-canary", "reason": "Last connection test failed; fix it and test again"},
                {"name": "S-off", "reason": "Disabled", "enabled": False},
                {"name": "S-zero", "reason": "0 targets left after the never-scan list"}])


def test_scope_items_of_a_run(api, world):
    w = _scope_run(world[0])
    p = posture(api, w["run"])
    by_key = {i["key"]: i for i in p["q0_items"]}
    host, net = w["S-host"]["uid"], w["R-net"]["uid"]
    # HF-4: "not_supported" that means "not read at this tier" is an unread scope; "the host has none" is not an item
    assert by_key[f"coverage:{host}:10.20.0.1:key and certificate files"]["reason"] == "coverage_gap"
    assert by_key[f"coverage:{host}:10.20.0.2:BitLocker"]["status"] == "denied"
    assert f"coverage:{host}:10.20.0.1:BitLocker" not in by_key
    assert by_key[f"coverage:{host}:10.20.0.1:package list"]["reason"] == "coverage_gap"
    assert by_key[f"coverage:{host}:10.20.0.9:target"]["status"] == "auth_failed"
    # FP-1: five addresses that answered on no port are not Q0 items, only a statistic
    assert not [k for k in by_key if "no answer" in k] and p["q_not_items"]["no_answer"] == 5
    assert p["q_not_items"]["not_present"] == 2  # BitLocker not installed, linkerd not installed
    # range non-answers of one network source: one item per (source, status) with a count and the addresses
    agg = by_key[f"coverage:{net}:*:timeout"]
    # review A: the network source's own timeout coverage rows and its timeout targets are one item
    assert agg["count"] == 5 and agg["addresses"] == ["10.231.0.17", "10.231.0.18", "10.231.1.0", "10.231.1.1",
                                                      "10.231.1.2"]
    assert sorted(agg["refs"]) == sorted(w["R-net"]["assets"][f"10.231.0.{i}#ports not answering"] for i in (17, 18))
    wait = by_key[f"source:{w['S-wait']['uid']}"]
    assert wait["reason"] == "source_not_read" and wait["detail"] == "collection not finished"
    assert by_key[f"source:{w['S-zero']['uid']}"]["reason"] == "excluded_by_choice"
    assert not [k for k in by_key if k.startswith(f"coverage:{w['S-ca']['uid']}:")]  # no AD CS CA: nothing there
    assert by_key[f"coverage:{net}:10.231.0.33:by_choice"]["reason"] == "excluded_by_choice"
    # sources: failed job, truncated job, lost assets, skipped by the planner (HF-5, HF-6)
    assert by_key[f"source:{w['S-fail']['uid']}"]["reason"] == "source_not_read"
    assert by_key[f"source:{w['S-trunc']['uid']}"]["reason"] == "source_truncated"
    lost = by_key[f"source:{w['S-lost']['uid']}"]
    assert lost["reason"] == "source_truncated" and lost["detail"] == {"reported": 9, "stored": 4}
    canary = by_key[f"source:{w['S-canary']['uid']}"]
    assert canary["reason"] == "source_not_read" and "connection test failed" in canary["detail"]
    assert by_key[f"source:{w['S-off']['uid']}"]["reason"] == "excluded_by_choice"
    # review B: a container image the node never read is Q0; a region with nothing enabled is not an item
    img = by_key[f"coverage:{w['K-img']['uid']}:reg.example/app:1:target"]
    assert img["reason"] == "coverage_gap" and img["status"] == "not_supported" and "zstd" in img["detail"]
    assert not [k for k in by_key if k.startswith(f"coverage:{w['C-aws']['uid']}:")]
    # by-choice coverage rows are keyed by their check like gaps (the reason is an attribute): two checks, two items
    kimg = w["K-img"]["uid"]
    assert by_key[f"coverage:{kimg}:reg.example/ok:2:Lambda env"]["reason"] == "excluded_by_choice"
    assert by_key[f"coverage:{kimg}:reg.example/ok:2:Batch env"]["count"] == 1
    # counts: q_grades over asset rows only (FP-4), Q0 items by reason, the decomposition
    assert sum(p["q_grades"].values()) == p["assets"] == 3
    assert p["q0_items_total"] == len(p["q0_items"]) == 16
    assert p["q0_reasons"] == {"coverage_gap": 6, "excluded_by_choice": 5, "source_not_read": 3, "source_truncated": 2}
    assert p["q0_counts"] == {"assets": 0, "scope_items": 16, "scope_rows": 20}
    # capped lists are ordered (kind rank, reason, key): inputs, sources, assets, then coverage (review A)
    rank = [(0 if i["key"].startswith("inputs:") else 1 if i["key"].startswith("source:")
             else 2 if i["key"].startswith("asset:") else 3, i["reason"], i["key"]) for i in p["q0_items"]]
    assert rank == sorted(rank)


def test_coverage_rows_carry_their_scope_item_on_the_list(api, world):
    w = _scope_run(world[0])
    listed = items(api, w["run"])
    host = w["S-host"]["assets"]
    tier1 = listed[host["10.20.0.1#key and certificate files"]]
    assert (tier1["q_grade"], tier1["q_reason"]) == ("Q0", "coverage_gap")
    assert tier1["q_item_key"].endswith(":10.20.0.1:key and certificate files")
    absent = listed[host["10.20.0.1#BitLocker"]]
    timeout = listed[w["R-net"]["assets"]["10.231.0.17#ports not answering"]]
    assert (timeout["q_grade"], timeout["q_item_key"]) == ("Q0", f"coverage:{w['R-net']['uid']}:*:timeout")
    silent = listed[w["R-net"]["assets"]["10.231.0.25#no answer"]]
    assert (silent["q_grade"], silent["q_reason"], silent["q_item_key"]) == (None, "not_an_item", None)
    assert (absent["q_grade"], absent["q_reason"], absent["q_item_key"]) == (None, "not_an_item", None)
    denied = listed[host["10.20.0.2#BitLocker"]]
    assert (denied["q_grade"], denied["q_reason"]) == ("Q0", "coverage_gap")
    assert detail(api, silent["id"])["q_reason"] == "not_an_item"


def _big_range(engine, tail: dict, head_timeouts: int = 0):
    """A network job as the node reports more than 1,000 targets: the first 1,000 rows, then one "summary" row
    whose error is the JSON {status: count} of the rest (jobctx.MAX_TARGET_ROWS)."""
    import json

    rows = [{"target": f"10.40.{i // 256}.{i % 256}", "status": "timeout" if i < head_timeouts else "ok"}
            for i in range(1000)]
    rows.append({"target": f"+{sum(tail.values())} more", "status": "summary", "error": json.dumps(tail)})
    return seed(engine, sources=[{"name": "R-big", "kind": "network_range", "result": {"targets": rows}}])


def test_a_fully_read_big_range_has_no_q0(api, world):
    w = _big_range(world[0], {"ok": 1048})
    assert posture(api, w["run"])["q0_items"] == []


def test_a_big_range_tail_is_counted_under_its_own_statuses(api, world):
    w = _big_range(world[0], {"ok": 700, "timeout": 300, "refused": 48}, head_timeouts=3)
    by_key = {i["key"]: i for i in posture(api, w["run"])["q0_items"]}
    uid = w["R-big"]["uid"]
    assert set(by_key) == {f"coverage:{uid}:*:timeout", f"coverage:{uid}:*:refused"}
    assert by_key[f"coverage:{uid}:*:timeout"]["count"] == 303 and len(by_key[f"coverage:{uid}:*:timeout"]["addresses"]) == 3
    assert by_key[f"coverage:{uid}:*:refused"]["count"] == 48 and by_key[f"coverage:{uid}:*:refused"]["addresses"] == []


def test_groups_left_out_of_a_run_are_excluded_by_choice(api, world):
    w = seed(world[0], include={"servers": True, "databases": False},
             sources=[{"name": "S", "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]}],
             idle=[{"name": "D-pg", "kind": "database"}])
    item = next(i for i in posture(api, w["run"])["q0_items"] if i["key"] == f"source:{w['D-pg']['uid']}")
    assert item["reason"] == "excluded_by_choice" and "left out of this run" in item["detail"]


def test_asset_q0_items_are_keyed_by_the_stable_asset_key(api, world, monkeypatch):
    from backend.utilities.cbom_sources import identity as ID

    facts = {"key_alg": "1.2.3.4.5.6.7", "not_after": "2030-01-01T00:00:00Z", "subject": "CN=x", "issuer": "CN=y"}
    keys = []
    for _ in range(2):  # two runs of the same source and asset: new row ids, one identity
        w = seed(world[0], sources=[{"name": f"S{len(keys)}", "uid": "uid-fixed",
                                     "assets": [_asset("certificate", "/etc/ssl/odd.pem", facts=facts)]}])
        d = detail(api, w[f"S{len(keys)}"]["assets"]["/etc/ssl/odd.pem"])
        assert (d["q_grade"], d["q_reason"]) == ("Q0", "unknown_verdict")
        keys.append(d["q_item_key"])
    with Session(world[0]) as s:
        row = s.get(CbomCollectedAsset, w["S1"]["assets"]["/etc/ssl/odd.pem"])
        want = "asset:" + ID.stable_key("node", "uid-fixed", ID.node_identity(row))
    assert keys[0] == keys[1] == want


def test_network_aggregate_keeps_the_first_1000_addresses(api, world):
    w = _scope_run(world[0], timeouts=1200)
    agg = next(i for i in posture(api, w["run"])["q0_items"] if i["key"].endswith(":*:timeout"))
    assert agg["count"] == 1202 and len(agg["addresses"]) == 1000  # 2 coverage rows + 1,200 targets
    assert agg["addresses"][:3] == ["10.231.0.17", "10.231.0.18", "10.231.1.0"]


def test_coverage_row_addresses_and_refs_are_capped_at_1000(api, world):
    rows = [_cov(f"10.50.{i // 256}.{i % 256}", "ports not answering", "timeout", "timed out") for i in range(1001)]
    w = seed(world[0], sources=[{"name": "R-cov", "kind": "network_range", "assets": rows}])
    item = next(i for i in posture(api, w["run"])["q0_items"] if i["key"].endswith(":*:timeout"))
    assert item["count"] == 1001 and len(item["addresses"]) == 1000 and len(item["refs"]) == 1000


def test_the_cap_never_drops_inputs_or_source_items(api, world):
    # review A repro: Mosca unset, 230 target timeouts and one failed source
    targets = [{"target": f"host-{i:03d}.corp", "status": "timeout"} for i in range(230)]
    w = seed(world[0], mosca={}, sources=[
        {"name": "S-many", "result": {"targets": targets},
         "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]},
        {"name": "S-fail", "status": "failure", "outcome": "failed"}])
    p = posture(api, w["run"])
    keys = [i["key"] for i in p["q0_items"]]
    assert p["q0_items_total"] == 232 and len(keys) == 200
    assert keys[:2] == ["inputs:mosca", f"source:{w['S-fail']['uid']}"]


@pytest.mark.parametrize("bad", [{"exposure": ["internet"]}, {"node_segment": {"name": "DMZ"}},
                                 {"exposure": {"x": 1}, "node_segment": ["DMZ"]}])
def test_malformed_job_metadata_does_not_break_the_grade(api, world, bad):
    # review A: legacy or corrupt snapshot values must not 500 every grade surface (unhashable memo keys)
    w = seed(world[0], sources=[{"name": "S", "metadata": bad,
                                 "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]}])
    aid = w["S"]["assets"]["10.20.0.1:443"]
    assert items(api, w["run"])[aid]["q_grade"] == "Q2"
    assert g(detail(api, aid)) == ("Q2", "qv_exceeds")
    assert posture(api, w["run"])["q_grades"]["Q2"] == 1


def test_the_inputs_digest_names_inputs_not_jobs(api, world):
    # review A: two runs with identical inputs share a digest (PR-3 compares digests across runs) ...
    spec = [{"name": "S", "uid": "uid-d", "metadata": {"data_lifetime_years": 3},
             "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]}]
    a = posture(api, seed(world[0], sources=spec)["run"])["grade_inputs"]["digest"]
    b = posture(api, seed(world[0], sources=[{**spec[0], "name": "S2"}])["run"])["grade_inputs"]["digest"]
    assert a == b
    # ... and a change of one job snapshot's X alone changes it
    c = posture(api, seed(world[0], sources=[{**spec[0], "name": "S3", "metadata": {"data_lifetime_years": 4}}])["run"])
    assert c["grade_inputs"]["digest"] != a


def test_q0_item_list_is_capped_at_200_with_the_total(api, world):
    targets = [{"target": f"host-{i:03d}.corp", "status": "timeout"} for i in range(230)]
    w = seed(world[0], sources=[{"name": "S-many", "result": {"targets": targets}}])
    p = posture(api, w["run"])
    assert len(p["q0_items"]) == 200 and p["q0_items_total"] == 230


# ----------------------------------------------------------------------------- one value per asset on every surface
def test_cross_surface_per_asset_equality(api, world):
    w = _scope_run(world[0])
    extra = seed(world[0], mosca=MOSCA, sources=[])  # noqa: F841  (a second run must not leak into the first)
    run = w["run"]
    listed = items(api, run)
    details = {aid: detail(api, aid) for aid in listed}
    explain_keys = {frozenset(d["q_explain"]) for d in details.values()}
    assert len(explain_keys) == 1, "q_explain has the same keys on every asset and coverage row"
    for d in details.values():
        assert {"q_grade", "q_label", "q_reason", "q_item_key", "q_explain"} <= set(d)
    for aid, it in listed.items():
        d = details[aid]
        assert (it["q_grade"], it["q_label"], it["q_reason"], it["q_item_key"]) == \
               (d["q_grade"], d["q_label"], d["q_reason"], d["q_item_key"]), aid
    p = posture(api, run)
    assets = Counter(it["q_grade"] or "none" for it in listed.values() if it["type"] != "coverage")
    assert {k: v for k, v in p["q_grades"].items() if v} == dict(assets)
    # every coverage row that is Q0 names an item the posture lists; Σ rows behind items == scope_rows
    keys = {i["key"] for i in p["q0_items"]}
    for it in listed.values():
        if it["type"] == "coverage" and it["q_grade"] == "Q0":
            assert it["q_item_key"] in keys, it
    assert sum(i["count"] for i in p["q0_items"] if i["kind"] == "scope") == p["q0_counts"]["scope_rows"]
    # the same inputs digest and model version on every grade-bearing response
    r = api("GET", f"/1/cbom/sources/runs/{run}/assets").json()
    digests = {r["grade_inputs"]["digest"], p["grade_inputs"]["digest"]}
    digests |= {d["q_explain"]["inputs_digest"] for d in details.values()}
    versions = {r["grade_model_version"], p["grade_model_version"]} | {d["q_explain"]["model_version"]
                                                                       for d in details.values()}
    assert len(digests) == 1 and len(versions) == 1
    assert p["grade_inputs"]["source"] == "current" and p["grade_inputs"]["mosca"] == {"x": 10, "y": 5, "z": 12}
    from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION

    e = next(iter(details.values()))["q_explain"]
    assert e["classifier_version"] == CLASSIFIER_VERSION and "run_classifier_version" in e


def test_inputs_digest_follows_team_inputs_and_the_job_snapshot(api, world):
    engine = world[0]
    w = seed(engine, sources=[{"name": "S", "metadata": {"data_lifetime_years": 1},
                               "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]}])
    aid = w["S"]["assets"]["10.20.0.1:443"]
    before = detail(api, aid)
    assert g(before) == ("Q3", "qv_within") and before["q_explain"]["x_basis"] == "source"
    # editing the source after Start does not regrade the run: X comes from the job's snapshot (FP-6)
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, w["S"]["source"])
        src.config = {**(src.config or {}), "data_lifetime_years": 50}
        s.add(src)
        s.commit()
    assert g(detail(api, aid)) == ("Q3", "qv_within")
    # editing the team's Z does: the record is graded with the team's current inputs until PR-2 snapshots them
    r = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"threat_years": 5}})
    assert r.status_code == 200, r.text
    after = detail(api, aid)
    assert g(after) == ("Q2", "qv_exceeds")
    assert after["q_explain"]["inputs_digest"] != before["q_explain"]["inputs_digest"]
    assert posture(api, w["run"])["grade_inputs"]["digest"] == after["q_explain"]["inputs_digest"]


def test_job_asset_list_carries_grades(api, world):
    w = seed(world[0], sources=[{"name": "S", "assets": [_asset("tls_endpoint", "10.20.0.1:443", facts=QV_TLS)]}])
    r = api("GET", f"/1/cbom/sources/jobs/{w['S']['job']}/assets")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["items"][0]["q_grade"], body["items"][0]["q_reason"]) == ("Q2", "qv_exceeds")
    assert body["grade_model_version"].startswith("qg-1+")


# ----------------------------------------------------------------------------- the grade-model route
def test_grade_model_route(api, world):
    from test_cbom_cb19_qgrade import PINNED_TEXT_SHA256

    r = api("GET", "/1/cbom/sources/grade-model")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "qg-1" and body["text_sha256"] == PINNED_TEXT_SHA256
    assert hashlib.sha256(body["text"].encode("utf-8")).hexdigest() == PINNED_TEXT_SHA256
    assert body["model_version"].startswith("qg-1+") and len(body["grades"]) == 5
    assert {r["code"] for r in body["reasons"]} >= {"coverage_gap", "source_not_read", "source_truncated",
                                                   "excluded_by_choice", "mosca_missing", "qv_exceeds_internet"}
    assert api("GET", "/2/cbom/sources/grade-model").status_code in (401, 403, 404)  # alice is not in team 2
