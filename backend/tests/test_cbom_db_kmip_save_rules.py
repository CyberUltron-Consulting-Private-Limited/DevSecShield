"""Database and KMIP source rules found on staging (14 Nov 2026), through the real API (same harness as
test_cbom_sources_api.py).

* #213: a KMIP client certificate and key are parsed and checked as one pair at save (as EJBCA's are, #190), and a PIN
  is refused for KMIP (only a PKCS#11 token uses one).
* #216: Oracle and MongoDB password logins need TLS and the server's CA, like MySQL, Redis and SQL Server.
* #217: ``db.bank.local:5433`` is not a host name: the port goes in the Port field (IPv6 literals keep their colons).
* #212: a KMIP connection test whose server was not verified (no CA) passes with a warning, not as a plain pass.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_ca_connectors_b3 import _pair  # noqa: E402
from test_cbom_node_keys import _ca_cert  # noqa: E402
from test_cbom_sources_api import PASSWORD, api, enroll_node, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSource  # noqa: E402
from backend.utilities.cbom_sources import kinds  # noqa: E402

ITEMS = "/1/cbom/sources/items"


def _kmip(node_id, cert, key, name="kmip-1", **secrets):
    return {"kind": "key_manager", "name": name, "node_id": node_id,
            "config": {"provider": "kmip", "host": "kmip.bank.local"},
            "secrets": {"client_cert": cert, "client_key": key, **secrets}}


def _db(node_id, engine, name, **cfg):
    config = {"engine": engine, "host": "db.bank.local", "login": "zs_cbom", **cfg}
    if engine == "oracle":
        config.setdefault("database_name", "ORCLPDB1")
    return {"kind": "database", "name": name, "node_id": node_id, "config": config, "secrets": {"password": PASSWORD}}


# ----------------------------------------------------------------------------- #213
def test_kmip_refuses_a_key_that_is_not_the_certificates_at_save(api, world):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    cert, key = _pair()
    _other, other_key = _pair("someone-else")
    r = api("POST", ITEMS, json=_kmip(node_id, cert, other_key))
    assert r.status_code == 400, r.text
    assert r.json()["detail"].startswith("secrets.client_key") and "does not belong" in r.json()["detail"]
    assert "PRIVATE KEY" not in r.text
    ok = api("POST", ITEMS, json=_kmip(node_id, cert, key))
    assert ok.status_code == 201, ok.text
    src = ok.json()["source"]
    r = api("PATCH", f"{ITEMS}/{src['id']}", json={"secrets": {"client_key": other_key},
                                                   "expected_version": src["row_version"]})
    assert r.status_code == 400 and "does not belong" in r.json()["detail"]


def test_kmip_refuses_a_key_that_only_looks_like_a_pem(api, world):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    cert, _key = _pair()
    r = api("POST", ITEMS, json=_kmip(node_id, cert, "garbage PRIVATE KEY-----"))
    assert r.status_code == 400 and r.json()["detail"].startswith("secrets.client_key: the private key could not be read")


def test_a_pin_is_refused_for_kmip_and_kept_for_pkcs11(api, world):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    cert, key = _pair()
    r = api("POST", ITEMS, json=_kmip(node_id, cert, key, pin="1234"))
    assert r.status_code == 400 and r.json()["detail"] == "secrets.pin: not used by this credential type", r.text
    hsm = api("POST", ITEMS, json={"kind": "key_manager", "name": "hsm-1", "node_id": node_id,
                                   "config": {"provider": "pkcs11", "module": "softhsm", "token_label": "lab-a"},
                                   "secrets": {"pin": "1234"}})
    assert hsm.status_code == 201 and hsm.json()["source"]["secrets_set"] == ["pin"]


def test_a_pin_stored_on_a_kmip_source_before_the_rule_is_dropped_on_the_next_save(api, world):  # noqa: F811
    engine, _ = world
    node_id, _token, _ = enroll_node(api)
    cert, key = _pair()
    src = api("POST", ITEMS, json=_kmip(node_id, cert, key)).json()["source"]
    from backend.utilities.cbom_sources.crypto import encrypt_secrets

    with Session(engine) as s:
        row = s.get(CbomCollectionSource, src["id"])
        row.secret_encrypted = encrypt_secrets({"client_cert": cert, "client_key": key, "pin": "1234"})
        row.secret_fields = ["client_cert", "client_key", "pin"]
        s.add(row)
        s.commit()
    cur = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    saved = api("PATCH", f"{ITEMS}/{src['id']}", json={"name": "kmip-renamed", "config": cur["config"],
                                                       "expected_version": cur["row_version"]})
    assert saved.status_code == 200, saved.text
    assert "pin" not in saved.json()["source"]["secrets_set"]


# ----------------------------------------------------------------------------- #216
@pytest.mark.parametrize("engine_name,label", [("oracle", "Oracle"), ("mongodb", "MongoDB")])
def test_oracle_and_mongodb_passwords_need_tls_and_the_ca(api, world, engine_name, label):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    for cfg in ({"require_tls": False}, {"require_tls": True}, {"require_tls": False, "ca_pem": _ca_cert()}):
        r = api("POST", ITEMS, json=_db(node_id, engine_name, f"{engine_name}-{len(cfg)}-{cfg['require_tls']}", **cfg))
        assert r.status_code == 400, (cfg, r.text)
        assert r.json()["detail"].startswith(f"ca_pem: {label} logins need TLS and the CA certificate")
    ok = api("POST", ITEMS, json=_db(node_id, engine_name, f"{engine_name}-ok", require_tls=True, ca_pem=_ca_cert()))
    assert ok.status_code == 201, ok.text


def test_a_mongodb_source_without_a_password_needs_no_ca(api, world):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    body = _db(node_id, "mongodb", "mongo-noauth", require_tls=False)
    body["config"].pop("login")  # no login: MongoDB without authentication, no password to protect
    body["secrets"] = {}
    assert api("POST", ITEMS, json=body).status_code == 201


# ----------------------------------------------------------------------------- #217
@pytest.mark.parametrize("host", ["db.bank.local:5433", "10.0.0.5:5432", "db:"])
def test_a_host_with_a_port_is_refused_with_the_port_field_named(api, world, host):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    r = api("POST", ITEMS, json=_db(node_id, "postgres", "pg-port", host=host))
    assert r.status_code == 422 or r.status_code == 400, r.text
    assert "Port field" in r.text


@pytest.mark.parametrize("host", ["db.bank.local", "10.0.0.5", "fd00::5", "2001:db8::1", "::ffff:10.0.0.5"])
def test_names_and_addresses_still_save(host):
    assert kinds.check_host(host) == host


# ----------------------------------------------------------------------------- #212
def test_a_kmip_test_without_a_ca_passes_with_a_warning(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    cert, key = _pair()
    src = api("POST", ITEMS, json=_kmip(node_id, cert, key)).json()["source"]
    job_id = api("POST", f"{ITEMS}/{src['id']}/test").json()["job"]["id"]
    lease = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()["job"]["lease_id"]
    warning = ("server not verified: no CA certificate is stored, so a server impersonating it could answer; upload "
               "the CA that issued the KMIP server's certificate")
    sample = {"target": "kmip.bank.local", "status": "ready", "reachable": True, "login": True,
              "note": "KMIP 2.0/1.4", "warning": warning}
    r = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers={"X-ZS-Node-Token": token},
            json={"lease_id": lease, "status": "success", "result": {"samples": [sample]}})
    assert r.status_code == 200, r.text
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["last_test_status"] == "partial"
    assert got["last_test_summary"] == f"1 of 1 samples ready, with a warning: {warning}"


def test_a_test_with_no_warning_still_passes_plainly(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    cert, key = _pair()
    src = api("POST", ITEMS, json=_kmip(node_id, cert, key)).json()["source"]
    job_id = api("POST", f"{ITEMS}/{src['id']}/test").json()["job"]["id"]
    lease = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()["job"]["lease_id"]
    api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers={"X-ZS-Node-Token": token},
        json={"lease_id": lease, "status": "success", "result": {"samples": [
            {"target": "kmip.bank.local", "status": "ready", "note": "KMIP 2.0"}]}})
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert (got["last_test_status"], got["last_test_summary"]) == ("passed", "1 of 1 samples ready")
