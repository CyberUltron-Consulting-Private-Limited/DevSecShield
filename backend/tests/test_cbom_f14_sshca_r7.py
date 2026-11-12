"""F1.4 review round 7 (PR #65 reviews 5871635994 security, 5871788632 code/QA, 5871815439 architecture).

One test (or more) per finding, written before the fix and run red on 22dca42 (log in $R6/f1-4/r7/), green after.
Same harness as ``test_cbom_f14_sshca.py`` (SQLite, the real routers and JWTs); the PostgreSQL tests (serials from a
SEQUENCE, the FOR SHARE check, the KRL index) run when ``CBOM_TEST_PG_URL`` is set, as in CI.
"""
from __future__ import annotations

import ast
import datetime as dt
import importlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from sqlmodel import Session, select

import test_cbom_f14_sshca as F
from backend.new_models import (
    CbomCollectionAuditEvent,
    CbomCollectionJob,
    CbomCollectionSource,
    CbomScanNode,
    TeamMembership,
    User,
)
from backend.utilities.cbom_sources import common
from backend.utilities.cbom_sources.sshca import ca as CA
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import claim as CLAIM
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import registry as R
from backend.utilities.cbom_sources.sshca import vault as V
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued

world, api, ca_world = F.world, F.api, F.ca_world
BASE = F.BASE
ROOT = Path(__file__).resolve().parents[2]
TRUST = "/cbom/ssh-ca-trust"
SOURCE_ITEMS = "/1/cbom/sources/items"
ARN_A = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"


def _mod(name: str):
    """A module this round adds (``pytest.fail`` with its name on the code before the fix, not an import error that
    would hide every other test of this file)."""
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        pytest.fail(f"{name} is missing ({exc})")


def _logs(monkeypatch) -> list[str]:
    lines: list[str] = []
    monkeypatch.setattr(common.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    return lines


def _audit(engine, action: str) -> list[CbomCollectionAuditEvent]:
    with Session(engine) as session:
        return list(session.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.action == action)
                                 .order_by(CbomCollectionAuditEvent.id)).all())


def _certs(engine) -> list[CbomSshCertIssued]:
    with Session(engine) as session:
        return list(session.exec(select(CbomSshCertIssued).order_by(CbomSshCertIssued.id)).all())


def _expire_soon(engine, seconds: int = 30) -> None:
    """The newest certificate has ``seconds`` left: a refresh is allowed."""
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued).order_by(CbomSshCertIssued.id.desc())).first()  # type: ignore[union-attr]
        row.valid_before = F._utcnow() + dt.timedelta(seconds=seconds)
        session.add(row)
        session.commit()


def _set_role(engine, user_id: int, role: str) -> None:
    with Session(engine) as session:
        row = session.exec(select(TeamMembership).where(TeamMembership.user_id == user_id,
                                                        TeamMembership.team_id == 1)).one()
        row.role = role
        session.add(row)
        session.commit()


def _ssh_ca_cfg(ca_id: int, **cfg) -> dict:
    return {"targets": ["10.20.0.5"], "credential_type": "ssh_ca", "ssh_ca_id": ca_id,
            "ssh_principals": ["zs-1-prod"], **cfg}


def _vault_token() -> str:
    return "hvs." + secrets.token_hex(8)  # generated at run time (no token-shaped literal in the repo)


def _reset_denials():
    mod = sys.modules.get("backend.utilities.cbom_sources.sshca.denials")
    if mod is not None:
        mod.reset()


@pytest.fixture(autouse=True)
def _fresh_state():
    _reset_denials()
    trust = sys.modules.get("backend.routers.cbom_sshca_trust")
    if trust is not None:
        trust.trust_limiter.requests.clear()
    yield
    KW.set_kms_client_factory(None)
    KW.forget()


# ============================================================================ major 1: the admin save gate
def test_a_member_cannot_create_or_switch_a_source_to_the_ssh_ca(api, ca_world):
    """sec M1 / QA issue.py:84: refused at save, like the vault credential."""
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    r = api("POST", SOURCE_ITEMS, "bob", json={"kind": "linux_servers", "name": "m", "node_id": node_id,
                                               "config": _ssh_ca_cfg(ca["id"])})
    assert r.status_code == 400 and "team admin" in r.json()["detail"], r.text
    mine = api("POST", SOURCE_ITEMS, "bob", json={"kind": "linux_servers", "name": "m2", "node_id": node_id,
                                                  "config": {"targets": ["10.20.0.6"]}})
    assert mine.status_code == 201, mine.text
    switched = api("PATCH", f"{SOURCE_ITEMS}/{mine.json()['source']['id']}", "bob",
                   json={"config": _ssh_ca_cfg(ca["id"], targets=["10.20.0.6"])})
    assert switched.status_code == 400 and "team admin" in switched.json()["detail"], switched.text


def test_a_member_cannot_rename_or_reenable_an_ssh_ca_source_but_can_turn_it_off(api, ca_world):
    """The member owns the source, an admin made it an SSH CA source: renaming it (P7's path) or turning it back on
    is an admin's save; turning it off is always allowed."""
    engine, _ = ca_world
    node_id, token, _ = F.enroll(api)
    ca = F.create_ca(api)
    mine = api("POST", SOURCE_ITEMS, "bob", json={"kind": "linux_servers", "name": "m", "node_id": node_id,
                                                  "config": {"targets": ["10.20.0.6"]}}).json()["source"]
    up = api("PATCH", f"{SOURCE_ITEMS}/{mine['id']}", "alice", json={"config": _ssh_ca_cfg(ca["id"])})
    assert up.status_code == 200, up.text
    rename = api("PATCH", f"{SOURCE_ITEMS}/{mine['id']}", "bob", json={"name": "renamed-by-member"})
    assert rename.status_code == 400 and "team admin" in rename.json()["detail"]
    off = api("PATCH", f"{SOURCE_ITEMS}/{mine['id']}", "bob", json={"enabled": False})
    assert off.status_code == 200 and off.json()["source"]["enabled"] is False
    on = api("PATCH", f"{SOURCE_ITEMS}/{mine['id']}", "bob", json={"enabled": True})
    assert on.status_code == 400 and "team admin" in on.json()["detail"]
    on = api("PATCH", f"{SOURCE_ITEMS}/{mine['id']}", "alice", json={"enabled": True, "test_after_save": True})
    assert on.status_code == 200, on.text
    p = F.claim(api, token)
    assert F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"]).status_code == 200


def test_offboarded_saver_blocks_certificates_until_an_admin_saves_again_even_unchanged(api, ca_world):
    """QA issue.py:84 + arch issue.py:83: the refusal names a remedy that works, an unchanged admin save is an
    audited approval, and the team sees which sources need it."""
    engine, ids = ca_world
    s = F.setup_job(api)
    _set_role(engine, ids["alice"], "member")
    _set_role(engine, ids["bob"], "admin")
    refused = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "no longer a team admin" in detail and "Save" in detail and "no change" in detail, detail
    listed = api("GET", BASE, "alice").json()
    need = listed.get("attention", {}).get("sources_needing_admin_save")
    assert need == [{"id": s["source"]["id"], "name": s["source"]["name"]}], listed.get("attention")
    with Session(engine) as session:
        cfg = dict(session.get(CbomCollectionSource, s["source"]["id"]).config)
    member_save = api("PATCH", f"{SOURCE_ITEMS}/{s['source']['id']}", "alice", json={"config": cfg})
    assert member_save.status_code == 400  # a member cannot approve
    same = api("PATCH", f"{SOURCE_ITEMS}/{s['source']['id']}", "bob", json={"config": cfg})
    assert same.status_code == 200, same.text
    assert same.json()["source"]["row_version"] == s["source"]["row_version"] + 1
    approvals = [e for e in _audit(engine, "source.update") if "ssh_ca.approved" in (e.changed_fields or [])]
    assert len(approvals) == 1 and approvals[0].actor_id == ids["bob"]
    ok = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert ok.status_code == 200, ok.text
    assert api("GET", BASE, "alice").json()["attention"]["sources_needing_admin_save"] == []
    again = api("PATCH", f"{SOURCE_ITEMS}/{s['source']['id']}", "bob", json={"config": cfg})
    assert again.json()["source"]["row_version"] == same.json()["source"]["row_version"]  # nothing to approve twice


def test_another_teams_principal_is_refused_at_save(api, ca_world):
    """sec nit kinds.py:207: the customer learns at save, not from a failed job."""
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    r = api("POST", SOURCE_ITEMS, json={"kind": "linux_servers", "name": "x", "node_id": node_id,
                                        "config": _ssh_ca_cfg(ca["id"], ssh_principals=["zs-2-prod"])})
    assert r.status_code == 400 and "another team" in r.json()["detail"], r.text


def test_principals_have_one_spelling(api, ca_world):
    """sec nit certs.py:32 (P9)."""
    assert C.principal_problem("zs-1-prod", 1) is None
    for spelling in ("zs-01-prod", "zs-0000000001-prod", "zs-00-prod"):
        assert C.principal_problem(spelling, 1) is not None, spelling
    assert C.principal_problem("zs-0-prod", 0) is None


def test_source_address_needs_a_real_prefix(api, ca_world):
    """sec certs.py:95 (P5): /0 and very short prefixes are refused at save and at issue."""
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    for wide in (["0.0.0.0/0"], ["::/0"], ["10.0.0.0/8"], ["2001:db8::/32"]):
        r = api("POST", SOURCE_ITEMS, json={"kind": "linux_servers", "name": "w", "node_id": node_id,
                                            "config": _ssh_ca_cfg(ca["id"], ssh_source_addresses=wide)})
        assert r.status_code == 400 and "prefix" in r.json()["detail"], (wide, r.text)
    for fine in (["10.20.0.0/16"], ["10.20.1.15"], ["2001:db8:1::/48"]):
        assert C.source_address_list(fine)
    with pytest.raises(C.CertError):
        C.source_address_list(["0.0.0.0/0"])


# ============================================================================ major 2: KMS cannot be opted out of
@pytest.fixture()
def moto_kms(monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        arns = [kms.create_key(Description=f"r7-{i}")["KeyMetadata"]["Arn"] for i in range(2)]
        KW.set_kms_client_factory(lambda region: boto3.client("kms", region_name=region))
        yield arns
        KW.set_kms_client_factory(None)


def test_fernet_is_refused_when_the_deployment_wraps_with_kms(api, ca_world, monkeypatch, moto_kms):
    """sec M2 (P1)."""
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    r = api("POST", BASE, json={"name": "downgrade", "key_wrap": "fernet"})
    assert r.status_code == 400 and "AWS KMS" in r.json()["detail"], r.text
    ok = F.create_ca(api, name="kms")
    assert ok["key_wrap"] == "aws_kms"


def test_rotation_moves_a_fernet_ca_onto_kms_and_off_a_retired_kms_key(api, ca_world, monkeypatch, moto_kms):
    """sec M2 + arch registry.py:214 (probes.txt 3)."""
    engine, _ = ca_world
    old = F.create_ca(api, name="old")  # created before the deployment configured KMS
    assert old["key_wrap"] == "fernet"
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    listed = api("GET", BASE).json()
    flagged = [c for c in listed["cas"] if c["id"] == old["id"]][0]
    assert flagged.get("wrap_warning") and "KMS" in flagged["wrap_warning"]
    rot = api("POST", f"{BASE}/{old['id']}/rotate", json={})
    assert rot.status_code == 201 and rot.json()["ca"]["key_wrap"] == "aws_kms", rot.text
    kms_ca = F.create_ca(api, name="on-a")
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[1])  # the operator retired key A from the allow-list
    rot2 = api("POST", f"{BASE}/{kms_ca['id']}/rotate", json={})
    assert rot2.status_code == 201, rot2.text
    with Session(engine) as session:
        assert session.get(CbomSshCa, rot2.json()["ca"]["id"]).kms_key_ref == moto_kms[1]
        row = session.get(CbomSshCa, kms_ca["id"])  # the existing CA still unwraps under A
        assert KW.unwrap(row.private_key_encrypted, team_id=1, ca_fingerprint=row.fingerprint)


def test_members_never_see_the_deployments_kms_arns(api, ca_world, monkeypatch, moto_kms):
    """sec minor cbom_sshca.py:114: an opaque label instead of the ARN (account id, region, key id)."""
    monkeypatch.setenv(KW.KMS_ENV, ",".join(moto_kms))
    ca = F.create_ca(api, name="kms")
    listed = api("GET", BASE, "bob")
    assert "arn:aws" not in listed.text and "arn:aws" not in api("GET", f"{BASE}/{ca['id']}", "bob").text
    labels = listed.json()["kms_keys"]
    assert [k.get("default") for k in labels] == [True, False] and all(k["label"].startswith("kms-") for k in labels)
    assert [c for c in listed.json()["cas"] if c["id"] == ca["id"]][0]["kms_key"] == labels[0]["label"]
    second = api("POST", BASE, json={"name": "second", "key_wrap": "aws_kms", "kms_key": labels[1]["label"]})
    assert second.status_code == 201 and second.json()["ca"]["kms_key"] == labels[1]["label"], second.text


# ============================================================================ major 3: refusals are audited and logged
def test_every_refused_certificate_request_leaves_one_audit_row_and_one_log_line(api, ca_world, monkeypatch):
    """sec M3 (P4)."""
    engine, _ = ca_world
    s = F.setup_job(api)
    _other_id, other_token, _ = F.enroll(api, name="dc-x")
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    lines = _logs(monkeypatch)
    cases = [("refresh_too_early", lambda: F.cert_route(api, s["token"], s["job_id"], s["lease"]), 400),
             ("lease_lost", lambda: F.cert_route(api, s["token"], s["job_id"], "wronglease0000"), 409),
             ("not_this_node", lambda: F.cert_route(api, other_token, s["job_id"], s["lease"]), 404)]
    for code, call, status in cases:
        before = len(_audit(engine, "sshca.cert.denied"))
        r = call()
        assert r.status_code == status, (code, r.text)
        rows = _audit(engine, "sshca.cert.denied")
        assert len(rows) == before + 1, code
        assert f"reason:{code}" in rows[-1].changed_fields and rows[-1].actor_type == "node", rows[-1].changed_fields
        assert [ln for ln in lines if "ssh certificate refused" in ln and f"reason={code}" in ln], (code, lines)
    assert len(_certs(engine)) == 1


def test_a_burst_of_refusals_is_bounded(api, ca_world, monkeypatch):
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    _logs(monkeypatch)
    for _ in range(20):
        assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 400
    assert len(_audit(engine, "sshca.cert.denied")) == 1


def test_the_claim_plugin_logs_why_it_did_not_mint(api, ca_world, monkeypatch):
    """sec M3: the claim path's refusal says why (it logged only that it refused)."""
    engine, _ = ca_world
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    source, test = F.ssh_ca_source(api, node_id, ca["id"])
    api("POST", f"{BASE}/{ca['id']}/revoke", json={"reason": "test"})
    lines = _logs(monkeypatch)
    now = F._utcnow()
    with Session(engine) as session:
        job = session.get(CbomCollectionJob, test["job_id"])
        job.status, job.lease_id, job.claimed_at = "claimed", "lease-plugin-1", now
        session.add(job)
        session.flush()
        out = CLAIM.claim_extras(session, session.get(CbomCollectionSource, source["id"]),
                                 session.get(CbomScanNode, node_id), now, {"config": {}, "secrets": {}})
        session.commit()
    assert "error" in out["config"]["ssh_ca"]
    assert [ln for ln in lines if "ssh certificate refused" in ln and "reason=no_active_ca" in ln], lines
    assert len(_audit(engine, "sshca.cert.denied")) == 1


# ============================================================================ major 4: the machine read path
def _token(api, who="alice", name="fleet") -> dict:
    r = api("POST", f"{BASE}/trust-tokens", who, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()


def _fetch(api, path: str, token: str | None, **headers):
    h = {"X-ZS-Fetcher": headers.pop("fetcher", "srv-01.bank.local"), **headers}
    if token:
        h["X-ZS-Trust-Token"] = token
    return api("GET", TRUST + path, None, headers=h)


def test_trust_tokens_are_admin_only_shown_once_and_revocable(api, ca_world):
    engine, _ = ca_world
    assert api("POST", f"{BASE}/trust-tokens", "bob", json={"name": "x"}).status_code == F.MEMBER_REFUSED
    made = _token(api)
    secret = made["token"]
    assert re.fullmatch(r"zst_[A-Za-z0-9_-]{40}", secret) and made["trust_token"]["prefix"] == secret[:8]
    listed = api("GET", f"{BASE}/trust-tokens", "bob")
    assert listed.status_code == 200 and secret not in listed.text and listed.json()["tokens"][0]["revoked_at"] is None
    assert _fetch(api, "/trusted-keys", secret).status_code == 200
    assert _audit(engine, "sshca.trust_token.create")
    rv = api("POST", f"{BASE}/trust-tokens/{made['trust_token']['id']}/revoke", json={})
    assert rv.status_code == 200 and _audit(engine, "sshca.trust_token.revoke")
    assert _fetch(api, "/trusted-keys", secret).status_code == 401
    assert _fetch(api, "/trusted-keys", None).status_code == 401
    assert _fetch(api, "/trusted-keys", "zst_" + "a" * 40).status_code == 401


def test_machine_path_serves_the_teams_trust_with_etags(api, ca_world):
    s = F.setup_job(api)
    secret = _token(api)["token"]
    other = api("POST", "/2/cbom/sources/fleet/ssh-ca", "carol", json={"name": "t2"}).json()["ca"]
    keys = _fetch(api, "/trusted-keys", secret)
    assert keys.status_code == 200 and s["ca"]["public_key"] in keys.text and other["public_key"] not in keys.text
    etag = keys.headers["etag"]
    gen = int(keys.headers["x-zs-trust-generation"])
    again = _fetch(api, "/trusted-keys", secret, **{"If-None-Match": etag})
    assert again.status_code == 304 and again.content == b""
    krl = _fetch(api, "/revoked", secret)
    assert krl.status_code == 200 and krl.content.startswith(b"SSHKRL\n\x00")
    assert _fetch(api, "/revoked", secret, **{"If-None-Match": krl.headers["etag"]}).status_code == 304
    assert _fetch(api, "/revoked", secret).content == krl.content  # stable bytes for one revocation generation
    pr = _fetch(api, "/principals?group=prod&group=db", secret)
    assert pr.status_code == 200 and pr.text.splitlines()[-2:] == ["zs-1-prod", "zs-1-db"]
    assert _fetch(api, "/principals?group=Bad Group", secret).status_code == 400
    # a revocation changes the KRL, its ETag and the generation
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    cert_id = api("GET", BASE + "/certificates").json()["certificates"][0]["id"]
    assert api("POST", f"{BASE}/certificates/{cert_id}/revoke", json={"reason": "x"}).status_code == 200
    krl2 = _fetch(api, "/revoked", secret, **{"If-None-Match": krl.headers["etag"]})
    assert krl2.status_code == 200 and krl2.content != krl.content
    assert int(krl2.headers["x-zs-trust-generation"]) > gen


def test_machine_path_is_off_with_the_flag_and_declares_a_machine_permission(api, ca_world, monkeypatch):
    secret = _token(api)["token"]
    trust = _mod("backend.routers.cbom_sshca_trust")
    for route in trust.router.routes:
        assert route.openapi_extra["x-zs-permission"].startswith("machine:"), route.path
    monkeypatch.setenv("CBOM_SSH_CA", "0")
    assert _fetch(api, "/trusted-keys", secret).status_code == 404


def test_fetchers_are_recorded_and_promote_shows_readiness(api, ca_world, monkeypatch):
    """arch cbom_sshca.py:128 (c) + registry.py:237: which bundle each fetcher has; promote waits a minimum age."""
    monkeypatch.setenv("CBOM_SSHCA_PROMOTE_MIN_AGE_S", "900")
    ca = F.create_ca(api)
    secret = _token(api)["token"]
    assert _fetch(api, "/trusted-keys", secret, fetcher="srv-01").status_code == 200
    assert _fetch(api, "/trusted-keys", secret, fetcher="srv-02").status_code == 200
    nxt = api("POST", f"{BASE}/{ca['id']}/rotate", json={}).json()["ca"]
    assert nxt["readiness"]["fetchers_total"] == 2 and nxt["readiness"]["fetchers_ready"] == 0
    assert _fetch(api, "/trusted-keys", secret, fetcher="srv-01").status_code == 200
    got = api("GET", f"{BASE}/{nxt['id']}").json()["ca"]
    assert got["readiness"]["fetchers_ready"] == 1 and got["readiness"]["fetchers_total"] == 2
    early = api("POST", f"{BASE}/{nxt['id']}/promote", json={})
    assert early.status_code == 400 and "force" in early.json()["detail"] and "1 of 2" in early.json()["detail"]
    forced = api("POST", f"{BASE}/{nxt['id']}/promote", json={"force": True})
    assert forced.status_code == 200 and forced.json()["ca"]["state"] == "active"
    tokens = api("GET", f"{BASE}/trust-tokens").json()["tokens"]
    assert tokens[0]["fetchers"] == 2


def test_templates_describe_the_machine_path_and_the_fetch_script_parses(api, ca_world, tmp_path):
    sshd = api("GET", BASE + "/templates/sshd-config").text
    assert "cron" not in sshd and "trust-fetch" in sshd and "X-ZS-Trust-Token" not in sshd  # the script sends it
    script = api("GET", BASE + "/templates/trust-fetch")
    assert script.status_code == 200 and script.text.startswith("#!/bin/sh")
    for needle in ("If-None-Match", "X-ZS-Trust-Token", "sshd -t", "ssh-keygen -Q -l", "mv -f", "tr -d '\\r'"):
        assert needle in script.text, needle
    assert "\r" not in script.text and "{{" not in script.text and "{team_id}" not in script.text  # formatted, no CR
    path = tmp_path / "zs-trust-fetch.sh"
    path.write_text(script.text)
    if shutil.which("sh"):
        assert subprocess.run(["sh", "-n", str(path)], capture_output=True).returncode == 0


def test_the_fleet_route_guard_accepts_machine_markers_on_machine_paths():
    """arch cbom_node_sshca.py:45: `machine:scan-node token`, no try/except import, guard relaxed for machine paths."""
    from backend.routers import cbom_node_sshca

    route = [r for r in cbom_node_sshca.router.routes if r.path.endswith("/ssh-cert")][0]
    assert route.openapi_extra == {"x-zs-permission": "machine:scan-node token"}
    assert "except ImportError" not in Path(cbom_node_sshca.__file__).read_text()


# ============================================================================ major 5: the unwrapped-key cache
def test_expired_cache_entries_are_swept_and_never_stay_resident(api, ca_world, monkeypatch):
    """sec M5 (P3) / arch keywrap.py:147."""
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    assert any(k[0] == s["ca"]["id"] for k in KW._cache)
    other = F.create_ca(api, name="other")
    real = time.monotonic
    monkeypatch.setattr(KW.time, "monotonic", lambda: real() + KW.CACHE_SECONDS + 5)
    with Session(engine) as session:
        row = session.get(CbomSshCa, other["id"])
        KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
    assert not any(k[0] == s["ca"]["id"] for k in KW._cache)  # swept by an unrelated call
    sweep = getattr(KW, "sweep", None)
    assert sweep is not None
    monkeypatch.setattr(KW.time, "monotonic", lambda: real() + 3 * KW.CACHE_SECONDS)
    sweep()
    assert KW._cache == {}


def test_an_inactive_ca_drops_its_cached_key_on_this_worker(api, ca_world):
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    with Session(engine) as session:  # another worker revoked it: this worker's forget() never ran
        row = session.get(CbomSshCa, s["ca"]["id"])
        row.state, row.revoked_at = "revoked", F._utcnow()
        session.add(row)
        session.commit()
        authority = CA.BuiltinCA(session, row)
        with pytest.raises(CA.IssueError):
            authority.issue(["zs-1-prod"], 300, public_key=s["line"], key_id="x", source_addresses=["10.0.0.1"])
    assert not any(k[0] == s["ca"]["id"] for k in KW._cache)


def test_cold_cache_unwraps_once_for_many_threads(api, ca_world, monkeypatch, moto_kms):
    engine, _ = ca_world
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    ca = F.create_ca(api, name="kms")
    import boto3

    calls: list[int] = []

    class Slow:
        def __init__(self):
            self.real = boto3.client("kms", region_name="us-east-1")

        def decrypt(self, **kw):
            calls.append(1)
            time.sleep(0.2)
            return self.real.decrypt(**kw)

    slow = Slow()
    KW.set_kms_client_factory(lambda region: slow)
    KW.forget()
    with Session(engine) as session:
        row = session.get(CbomSshCa, ca["id"])
        args = (row.id, 1, row.fingerprint, row.private_key_encrypted)
    errors: list[BaseException] = []

    def one():
        try:
            KW.cached_private_key(*args)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=one) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and len(calls) == 1


# ============================================================================ major 7: autogenerate sees the tables
def test_alembic_env_imports_every_table_model():
    """QA models.py:29: env.py's imports must register every ``table=True`` model under backend/ (else autogenerate
    emits drop_table for them)."""
    env = ROOT / "prod_database_migrations" / "migrations" / "env.py"
    modules = []
    for node in ast.walk(ast.parse(env.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("backend"):
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules += [a.name for a in node.names if a.name.startswith("backend")]
    tables = set()
    for path in (ROOT / "backend").rglob("*.py"):
        if ".venv" in path.parts or "tests" in path.parts:
            continue
        text = path.read_text(errors="replace")
        if "table=True" not in text:
            continue
        tables |= set(re.findall(r'__tablename__\s*=\s*["\']([a-z0-9_]+)["\']', text))
    code = ("import json, sys\n" + "".join(f"import {m}\n" for m in modules)
            + "from sqlmodel import SQLModel\nprint(json.dumps(sorted(SQLModel.metadata.tables)))\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT),
                         env={**os.environ, "PYTHONPATH": str(ROOT)}, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    registered = set(json.loads(out.stdout.strip().splitlines()[-1]))
    assert {"cbomsshca", "cbomsshcertissued"} <= tables
    assert sorted(tables - registered) == []


# ============================================================================ major 8: serials and the CA row (PostgreSQL)
PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")


def _pg_world(cas: int = 1):
    """A PostgreSQL schema with one team, one admin, ``cas`` CAs, each with a node, a source and a claimed job."""
    from sqlalchemy import create_engine
    from sqlmodel import SQLModel

    from backend.new_models import Team

    engine = create_engine(PG, pool_size=12, max_overflow=4)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    now = F._utcnow()
    out = []
    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=10.0))
        s.commit()
        user = User(email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        for i in range(cas):
            node = CbomScanNode(team_id=1, owner_user_id=user.id, name=f"n{i}", node_token_hash=f"{i:064d}",
                                ssh_public_key=F.node_key_line()[1], source_ips=["10.0.0.5"], enrolled_at=now)
            s.add(node)
            s.flush()

            class Body:
                name, provider, key_alg, key_wrap, kms_key_ref, kms_key = f"ca{i}", "builtin", "ed25519", None, None, None
                vault_config, secrets, default_ttl_s = None, None, 300

            ca = R.create_ca(s, 1, user.id, Body(), now)
            src = CbomCollectionSource(team_id=1, owner_user_id=user.id, updated_by_user_id=user.id,
                                       kind="linux_servers", name=f"s{i}", name_lower=f"s{i}", node_id=node.id,
                                       config=_ssh_ca_cfg(ca.id))
            s.add(src)
            s.flush()
            job = CbomCollectionJob(team_id=1, source_id=src.id, node_id=node.id, kind="collect", status="claimed",
                                    lease_id=f"lease-{i:08d}", claimed_at=now)
            s.add(job)
            s.commit()
            out.append({"node": node.id, "job": job.id, "source": src.id, "ca": ca.id, "user": user.id})
    return engine, out


def _mint(engine, ids: dict, hold_s: float = 0.0, via: str = "claim") -> float:
    from backend.utilities.cbom_sources.sshca.issue import issue_for_job

    t = time.perf_counter()
    with Session(engine) as s:
        issue_for_job(s, s.get(CbomScanNode, ids["node"]), s.get(CbomCollectionJob, ids["job"]),
                      s.get(CbomCollectionSource, ids["source"]), F._utcnow(), via=via)
        if hold_s:
            time.sleep(hold_s)
        s.commit()
    return time.perf_counter() - t


@needs_pg
def test_pg_a_mint_never_waits_behind_another_open_mint(monkeypatch):
    """arch ca.py:113: the second mint of the same CA does not wait for the first transaction to commit."""
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    KW.forget()
    engine, ids = _pg_world(1)
    _mint(engine, ids[0])  # warm the key cache
    first = threading.Thread(target=_mint, args=(engine, ids[0], 1.5))
    first.start()
    time.sleep(0.3)
    took = _mint(engine, ids[0])
    first.join()
    assert took < 0.6, took
    serials = [r.serial for r in _certs(engine)]
    assert len(serials) == len(set(serials)) == 3


@needs_pg
def test_pg_revoke_waits_for_mints_in_flight_and_then_nothing_is_signed(monkeypatch):
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    KW.forget()
    engine, ids = _pg_world(1)
    _mint(engine, ids[0])
    minting = threading.Thread(target=_mint, args=(engine, ids[0], 1.0))
    minting.start()
    time.sleep(0.3)
    t = time.perf_counter()
    with Session(engine) as s:
        R.revoke(s, s.get(CbomSshCa, ids[0]["ca"]), ids[0]["user"], "test", F._utcnow())
        s.commit()
    waited = time.perf_counter() - t
    minting.join()
    assert waited >= 0.4, waited
    with pytest.raises(CA.IssueError):
        _mint(engine, ids[0])
    assert len(_certs(engine)) == 2


@needs_pg
def test_pg_serials_are_unique_under_concurrency_and_the_sequence_exists(monkeypatch):
    from sqlalchemy import text

    monkeypatch.setenv("CBOM_SSH_CA", "1")
    KW.forget()
    engine, ids = _pg_world(2)
    with engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM pg_class WHERE relkind = 'S' AND relname = "
                              "'cbomsshca_serial_seq'")).scalar() == 1
    threads = [threading.Thread(target=_mint, args=(engine, ids[i % 2])) for i in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    rows = _certs(engine)
    assert len(rows) == 16 and len({(r.ca_id, r.serial) for r in rows}) == 16


# ============================================================================ major 9: KMS and the claim
def _stubbed_kms(code: str | None, *, sleep: float = 0.0):
    """A KMS client whose Decrypt answers ``code`` (an AWS error code) through botocore's Stubber."""
    import boto3
    from botocore.config import Config
    from botocore.stub import Stubber

    client = boto3.client("kms", region_name="us-east-1", config=Config(retries={"mode": "standard", "max_attempts": 1}))
    stub = Stubber(client)
    for _ in range(4):
        if code is None:
            stub.add_response("decrypt", {"Plaintext": b"\x00" * 32, "KeyId": ARN_A})
        else:
            stub.add_client_error("decrypt", service_error_code=code, service_message="refused by the stub",
                                  http_status_code=400 if code != "KMSInternalException" else 500)
    stub.activate()
    return client


def _kms_ca(api, engine, monkeypatch, moto_kms) -> dict:
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    s = F.setup_job(api)
    KW.forget()
    return s


@pytest.mark.parametrize("code, status, words", [
    ("AccessDeniedException", 400, "kms:Decrypt"),
    ("DisabledException", 400, "disabled or pending deletion"),
    ("KMSInvalidStateException", 400, "disabled or pending deletion"),
    ("ThrottlingException", 503, "try again"),
    ("KMSInternalException", 503, "try again"),
])
def test_kms_errors_reach_the_node_as_plain_text_and_transient_ones_as_503(api, ca_world, monkeypatch, moto_kms,
                                                                           code, status, words):
    """QA keywrap.py:134: no class names; a throttle is retryable (503 + Retry-After), a missing grant is not."""
    engine, _ = ca_world
    s = _kms_ca(api, engine, monkeypatch, moto_kms)
    KW.set_kms_client_factory(lambda region: _stubbed_kms(code))
    r = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == status, r.text
    detail = r.json()["detail"]
    assert words in detail and "Exception" not in detail and "arn:aws" not in detail, detail
    if status == 503:
        assert int(r.headers["retry-after"]) >= 1
    assert _certs(engine) == []


def test_the_claim_never_calls_kms_on_a_cold_cache_and_a_kms_failure_is_retryable(api, ca_world, monkeypatch,
                                                                                    moto_kms):
    """arch claim.py:52: mint at claim only from a warm cache (or fernet); otherwise fetch."""
    engine, _ = ca_world
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    source, test = F.ssh_ca_source(api, node_id, ca["id"])
    KW.forget()
    called: list[str] = []

    class Spy:
        def decrypt(self, **kw):
            called.append("decrypt")
            raise AssertionError("KMS called inside the claim")

    KW.set_kms_client_factory(lambda region: Spy())
    now = F._utcnow()
    with Session(engine) as session:
        job = session.get(CbomCollectionJob, test["job_id"])
        job.status, job.lease_id, job.claimed_at = "claimed", "lease-plugin-1", now
        session.add(job)
        session.flush()
        out = CLAIM.claim_extras(session, session.get(CbomCollectionSource, source["id"]),
                                 session.get(CbomScanNode, node_id), now, {"config": {}, "secrets": {}})
        session.commit()
    assert out["config"]["ssh_ca"] == {"fetch": True} and called == []


def test_a_transient_kms_error_at_claim_is_fetch_not_error(api, ca_world, monkeypatch, moto_kms):
    engine, _ = ca_world
    monkeypatch.setenv(KW.KMS_ENV, moto_kms[0])
    node_id, _token, _ = F.enroll(api)
    ca = F.create_ca(api)
    source, test = F.ssh_ca_source(api, node_id, ca["id"])
    now = F._utcnow()
    with Session(engine) as session:  # a warm cache whose entry is about to be re-checked: force the KMS path
        job = session.get(CbomCollectionJob, test["job_id"])
        job.status, job.lease_id, job.claimed_at = "claimed", "lease-plugin-1", now
        session.add(job)
        session.flush()
        src, node = session.get(CbomCollectionSource, source["id"]), session.get(CbomScanNode, node_id)
        monkeypatch.setattr(KW, "is_cached", lambda *a, **k: True, raising=False)  # the claim thinks it is warm
        KW.forget()
        KW.set_kms_client_factory(lambda region: _stubbed_kms("ThrottlingException"))
        out = CLAIM.claim_extras(session, src, node, now, {"config": {}, "secrets": {}})
        session.commit()
    assert out["config"]["ssh_ca"] == {"fetch": True}, out


def test_one_kms_client_per_region_with_short_timeouts_and_standard_retries(monkeypatch):
    KW.set_kms_client_factory(None)
    monkeypatch.setattr(KW, "_clients", {}, raising=False)
    a, b = KW._kms("us-east-1"), KW._kms("us-east-1")
    assert a is b and KW._kms("eu-west-1") is not a
    cfg = a.meta.config
    assert (cfg.connect_timeout, cfg.read_timeout) == (2, 5)
    assert cfg.retries == {"mode": "standard", "total_max_attempts": 3}  # 3 attempts in all, standard mode


# ============================================================================ minors
def test_a_revoked_certificate_is_not_replaced_for_that_job(api, ca_world):
    """sec issue.py:108 (P12): the job stops instead of getting the next certificate at once."""
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    cert_id = api("GET", BASE + "/certificates").json()["certificates"][0]["id"]
    assert api("POST", f"{BASE}/certificates/{cert_id}/revoke", json={"reason": "suspected leak"}).status_code == 200
    again = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert again.status_code == 409 and again.json()["detail"].startswith("Stop this job") \
        and "revoked" in again.json()["detail"], again.text
    assert len(_certs(engine)) == 1


def test_a_node_key_shared_with_another_node_gets_no_certificate(api, ca_world):
    """sec issue.py:127 (P8): cloned images; another team's node with the same key counts too."""
    engine, _ = ca_world
    s = F.setup_job(api)
    r = api("POST", "/2/cbom/sources/nodes", "carol", json={"name": "t2-twin-node", "segment": "dc"})
    e = api("POST", "/cbom/node/enroll", None, json={
        "registration_token": r.json()["registration_token"], "hostname": "t2-twin-node", "version": "1.2",
        "source_ips": ["10.0.0.7"], "ssh_public_key": s["line"], "capabilities": {"collectors": ["linux_ssh"]}})
    assert e.status_code == 200
    refused = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert refused.status_code == 400 and "re-key" in refused.json()["detail"].lower(), refused.text
    assert "team 2" not in refused.text and "t2-twin" not in refused.text  # nothing about the other node
    assert _certs(engine) == []


def test_vault_approle_tokens_are_revoked_after_signing(api, ca_world, monkeypatch):
    """sec vault.py:176: each AppRole login's token is revoked (revoke-self) once the certificate is signed."""
    fake = F.FakeVault()
    monkeypatch.setattr(V, "call", fake)
    r = api("POST", BASE, json={"name": "vault", "provider": "vault",
                                "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                "secrets": {"role_id": "role-0000-0000", "secret_id": "xxxxxxxx-0000"}})
    ca = r.json()["ca"]
    node_id, token, _ = F.enroll(api)
    F.ssh_ca_source(api, node_id, ca["id"])
    p = F.claim(api, token)
    assert F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"]).status_code == 200
    paths = [c[1] for c in fake.calls]
    sign = paths.index("/v1/ssh-client-signer/sign/zs-cbom")
    assert "/v1/auth/token/revoke-self" in paths[sign:], paths
    revoke = [c for c in fake.calls if c[1] == "/v1/auth/token/revoke-self"][-1]
    signed_with = [c for c in fake.calls if "/sign/" in c[1]][-1][3]
    assert revoke[3] == signed_with and signed_with  # the AppRole login's own token, revoked by itself


def test_vault_superset_principals_and_post_dated_certificates_are_refused(api, ca_world, monkeypatch):
    """QA ca.py:198 (mutant P3) and ca.py:200 (mutant T10)."""
    engine, _ = ca_world
    fake = F.FakeVault()
    monkeypatch.setattr(V, "call", fake)
    ca = api("POST", BASE, json={"name": "vault", "provider": "vault",
                                 "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                 "secrets": {"token": _vault_token()}}).json()["ca"]
    node_id, token, _ = F.enroll(api)
    F.ssh_ca_source(api, node_id, ca["id"])
    p = F.claim(api, token)
    fake.mutate = {"principals": ["zs-1-prod", "root"]}
    r = F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"])
    assert r.status_code == 400 and "principals differ" in r.json()["detail"], r.text
    real_call = fake.__call__

    def post_dated(cfg, method, path, *, token=None, body=None):
        if "/sign/" not in path:
            return real_call(cfg, method, path, token=token, body=body)
        fake.not_before = -3000  # valid_after = now + 3000
        try:
            return real_call(cfg, method, path, token=token, body={**body, "ttl": "3240s"})
        finally:
            fake.not_before = 30

    fake.mutate = {}
    monkeypatch.setattr(V, "call", post_dated)
    r = F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"])
    assert r.status_code == 400 and "validity" in r.json()["detail"], r.text
    assert _certs(engine) == []


def test_the_vault_audit_row_records_the_certificates_real_validity(api, ca_world, monkeypatch):
    """QA ca.py:200 (mutant A14)."""
    engine, _ = ca_world
    fake = F.FakeVault()
    monkeypatch.setattr(V, "call", fake)
    ca = api("POST", BASE, json={"name": "vault", "provider": "vault",
                                 "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                 "secrets": {"token": _vault_token()}}).json()["ca"]
    node_id, token, _ = F.enroll(api)
    F.ssh_ca_source(api, node_id, ca["id"])
    p = F.claim(api, token)
    out = F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"]).json()
    facts = C.read_cert(out["certificate"])
    row = _certs(engine)[0]
    assert F._epoch(row.valid_after) == facts.valid_after and F._epoch(row.valid_before) == facts.valid_before
    assert CA.from_db_serial(row.serial) == facts.serial and row.key_id == facts.key_id


def test_revoking_one_certificate_is_audited(api, ca_world):
    """QA registry.py:283 (mutant A12)."""
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    cert_id = api("GET", BASE + "/certificates").json()["certificates"][0]["id"]
    assert api("POST", f"{BASE}/certificates/{cert_id}/revoke", json={"reason": "x"}).status_code == 200
    rows = _audit(engine, "sshca.cert.revoke")
    assert [(r.object_type, r.object_id) for r in rows] == [("ssh_cert", cert_id)]


def test_a_job_that_must_stop_gets_no_new_certificate(api, ca_world):
    """QA cbom_node_sshca.py:79 (mutant S1): cancelled, disabled or changed source -> 409 'Stop this job'."""
    engine, _ = ca_world
    s = F.setup_job(api)
    with Session(engine) as session:
        job = session.get(CbomCollectionJob, s["job_id"])
        job.cancel_requested_at, job.cancel_reason = F._utcnow(), "Cancelled by alice"
        session.add(job)
        session.commit()
    r = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == 409 and r.json()["detail"] == "Stop this job: Cancelled by alice"
    s2_node, s2_token, _ = F.enroll(api, name="dc-2")
    src2, test2 = F.ssh_ca_source(api, s2_node, s["ca"]["id"], name="second")
    p2 = F.claim(api, s2_token)
    changed = api("PATCH", f"{SOURCE_ITEMS}/{src2['id']}",  # a new target: the source's connection version moves
                  json={"config": _ssh_ca_cfg(s["ca"]["id"], targets=["10.20.0.99"])})
    assert changed.status_code == 200, changed.text
    r2 = F.cert_route(api, s2_token, p2["job"]["id"], p2["job"]["lease_id"])
    assert r2.status_code == 409 and r2.json()["detail"].startswith("Stop this job"), r2.text
    assert _certs(engine) == []


def test_a_reclaimed_job_gets_its_first_certificate(api, ca_world):
    """QA nit issue.py:110 (mutant T15): after a lease timeout and a re-claim by the same node, the old attempt's
    certificate does not count."""
    engine, _ = ca_world
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    with Session(engine) as session:  # the lease ran out and the job went back to pending
        job = session.get(CbomCollectionJob, s["job_id"])
        job.status, job.lease_id, job.claimed_at = "pending", None, None
        session.add(job)
        session.commit()
    time.sleep(1.1)  # claimed_at has second resolution on some databases
    p = F.claim(api, s["token"])
    assert p["job"]["id"] == s["job_id"]
    r = F.cert_route(api, s["token"], s["job_id"], p["job"]["lease_id"])
    assert r.status_code == 200, r.text


def test_list_does_not_count_every_certificate_and_one_ca_counts_on_demand(api, ca_world, monkeypatch):
    """arch cbom_sshca.py:100."""
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    from backend.routers import cbom_sshca

    assert not hasattr(cbom_sshca, "_issued_counts")
    listed = api("GET", BASE).json()["cas"][0]
    assert listed.get("issued_count") is None
    assert api("GET", f"{BASE}/{s['ca']['id']}").json()["ca"]["issued_count"] == 1


def test_audit_retention_deletes_rows_older_than_13_months_in_batches(api, ca_world):
    """arch migration:95."""
    engine, _ = ca_world
    retention = _mod("backend.utilities.cbom_sources.sshca.retention")
    s = F.setup_job(api)
    now = F._utcnow()
    with Session(engine) as session:
        for i in range(12):
            session.add(CbomSshCertIssued(team_id=1, ca_id=s["ca"]["id"], serial=1000 + i, key_id="old",
                                          valid_after=now, valid_before=now, cert_public_key_sha256="0" * 64,
                                          issued_at=now - dt.timedelta(days=400 if i < 10 else 300)))
        session.commit()
    out = retention.purge(engine, now, batch=3)
    assert out["certificates"] == 10 and out["batches"] >= 4
    left = _certs(engine)
    assert len(left) == 2 and all(r.issued_at > now - dt.timedelta(days=396) for r in left)


def test_audit_table_indexes_serve_the_listing_and_the_krl():
    """arch migration:95 + registry.py:293; QA nit (redundant ca_id index)."""
    names = {i.name: ([c.name for c in i.columns], i) for i in CbomSshCertIssued.__table__.indexes}
    assert "ix_cbomsshcertissued_ca_id" not in names
    cols = {tuple(v[0]) for v in names.values()}
    assert {("team_id", "id"), ("team_id", "node_id", "id"), ("team_id", "ca_id", "id"),
            ("team_id", "valid_before")} <= cols, cols
    partial = [v[1] for v in names.values() if tuple(v[0]) == ("team_id", "valid_before")][0]
    assert "revoked_at IS NOT NULL" in str(partial.dialect_options["postgresql"]["where"])


def test_vault_rotation_onto_another_issuer_has_no_gap(api, ca_world, monkeypatch):
    """arch vault.py:166: rotate registers the next key from another issuer (or mount) while the active row keeps
    signing through its own; promote switches; the certificates are checked against each row's key."""
    old, new = F.FakeVault(), F.FakeVault()

    def routed(cfg, method, path, *, token=None, body=None):
        if "/issuer/next-key/" in path or (cfg.get("issuer_ref") == "next-key" and "/sign/" in path) \
                or path.startswith("/v1/ssh-next/"):
            return new(cfg, method, path, token=token, body=body)
        return old(cfg, method, path, token=token, body=body)

    monkeypatch.setattr(V, "call", routed)
    ca = api("POST", BASE, json={"name": "vault", "provider": "vault",
                                 "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                 "secrets": {"token": _vault_token()}}).json()["ca"]
    node_id, token, _ = F.enroll(api)
    F.ssh_ca_source(api, node_id, ca["id"])
    rot = api("POST", f"{BASE}/{ca['id']}/rotate",
              json={"vault_config": {"issuer_ref": "next-key", "role": "zs-cbom-next"}})
    assert rot.status_code == 201, rot.text
    nxt = rot.json()["ca"]
    assert nxt["public_key"] == new.public and nxt["vault_config"]["issuer_ref"] == "next-key"
    p = F.claim(api, token)
    before = F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"])
    assert before.status_code == 200 and C.read_cert(before.json()["certificate"]).signature_key_blob == \
        C.public_blob(old.public)
    assert api("POST", f"{BASE}/{nxt['id']}/promote", json={"force": True}).status_code == 200
    engine, _ = ca_world
    _expire_soon(engine)
    after = F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"])
    assert after.status_code == 200, after.text
    assert C.read_cert(after.json()["certificate"]).signature_key_blob == C.public_blob(new.public)
    sign_paths = [c[1] for c in new.calls if "/sign/" in c[1]]
    assert sign_paths == ["/v1/ssh-client-signer/sign/zs-cbom-next"]


def test_an_unknown_provider_is_refused_not_signed_as_builtin(api, ca_world):
    """arch nit issue.py:125."""
    engine, _ = ca_world
    s = F.setup_job(api)
    with Session(engine) as session:
        row = session.get(CbomSshCa, s["ca"]["id"])
        row.provider = "node"
        session.add(row)
        session.commit()
    r = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == 400 and "provider" in r.json()["detail"], r.text
    with Session(engine) as session:
        with pytest.raises(CA.IssueError, match="provider"):
            CA.ca_for(session, 1, s["ca"]["id"])
