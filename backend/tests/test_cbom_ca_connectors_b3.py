"""Certificate authority sources: ask only for what is used (C6), check the EJBCA client key at save (C7), serve the
latest collection result next to the latest test so the card can say one honest status (C8), and label EJBCA
profiles from the key algorithms they allow (C10d).  Owner bugs of 14 Nov 2026.

Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlmodel import Session
from test_cbom_sources_api import (  # noqa: F401
    _collect_job,
    api,
    enroll_node,
    world,
)

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources import algid, kinds
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources.crypto import encrypt_secrets

NOT_COLLECTED = ("venafi", "keyfactor", "digicert", "sectigo", "other")


# ----------------------------------------------------------------------------- helpers
def _pair(cn: str = "zs-reader", *, curve: bool = False):
    """A self-signed client certificate and its key (made here; no key material in the repository)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1()) if curve else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode()
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return pem_cert, pem_key


def _ejbca(node_id, cert, key, name="ejbca-1"):
    return {"kind": "ca_connector", "name": name, "node_id": node_id,
            "config": {"provider": "ejbca", "api_url": "https://ejbca.corp"},
            "secrets": {"client_cert": cert, "client_key": key}}


# ----------------------------------------------------------------------------- C6: no key for kinds with no collector
@pytest.mark.parametrize("provider", NOT_COLLECTED)
def test_ca_kinds_without_a_collector_ask_for_no_key(provider):
    spec = kinds.KINDS["ca_connector"]
    cfg = spec.model.model_validate({"provider": provider, "api_url": "https://clm.example.com"})
    assert not spec.collectable(cfg)
    assert spec.secret_fields(cfg) == set() and "api_key" not in spec.optional_secrets


def test_a_ca_without_a_collector_saves_without_a_key_and_refuses_one(api, world):  # noqa: F811  (the API fixtures)
    body = {"kind": "ca_connector", "name": "kf", "config": {"provider": "keyfactor", "api_url": "https://kf.corp"}}
    r = api("POST", "/1/cbom/sources/items", json={**body, "secrets": {}})
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["secrets_set"] == [] and src["last_test_status"] == "not_available"
    r = api("POST", "/1/cbom/sources/items", json={**body, "name": "kf-2", "secrets": {"api_key": "kf-key-123"}})
    assert r.status_code == 400 and "not used" in r.json()["detail"]
    assert "kf-key-123" not in r.text


def test_a_key_stored_before_the_fix_is_never_served_and_cleared_on_the_next_save(api, world):  # noqa: F811  (the API fixtures)
    engine, ids = world
    now = utcnow()
    with Session(engine) as s:
        row = CbomCollectionSource(team_id=1, owner_user_id=ids["alice"], kind="ca_connector", name="Venafi",
                                   name_lower="venafi", config={"provider": "venafi", "api_url": "https://tpp.corp/vedsdk"},
                                   secret_encrypted=encrypt_secrets({"api_key": "legacy-key-9"}), secret_fields=["api_key"],
                                   created_at=now, last_updated=now, last_test_status="not_available")
        s.add(row)
        s.commit()
        s.refresh(row)
        source_id, version = row.id, row.row_version
    got = api("GET", f"/1/cbom/sources/items/{source_id}").json()["source"]
    assert "legacy-key-9" not in str(got)
    r = api("PATCH", f"/1/cbom/sources/items/{source_id}", json={"name": "Venafi TPP", "expected_version": version})
    assert r.status_code == 200, r.text
    assert r.json()["source"]["secrets_set"] == []
    with Session(engine) as s:
        row = s.get(CbomCollectionSource, source_id)
        assert row.secret_fields == [] and "legacy-key-9" not in str(row.secret_encrypted)


# ----------------------------------------------------------------------------- C7: EJBCA key checked at save
def test_ejbca_refuses_a_key_that_is_not_the_certificates_at_save(api, world):  # noqa: F811  (the API fixtures)
    node_id, _token, _ = enroll_node(api)
    cert, key = _pair()
    _other_cert, other_key = _pair("someone-else")
    r = api("POST", "/1/cbom/sources/items", json=_ejbca(node_id, cert, other_key))
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail.startswith("secrets.client_key") and "does not belong to the client certificate" in detail
    assert "PRIVATE KEY" not in r.text
    ok = api("POST", "/1/cbom/sources/items", json=_ejbca(node_id, cert, key))
    assert ok.status_code == 201, ok.text
    ec_cert, ec_key = _pair("ec-reader", curve=True)
    assert api("POST", "/1/cbom/sources/items", json=_ejbca(node_id, ec_cert, ec_key, "ejbca-ec")).status_code == 201
    # an edit that replaces only the key is checked against the stored certificate
    src = ok.json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}",
            json={"secrets": {"client_key": other_key}, "expected_version": src["row_version"]})
    assert r.status_code == 400 and "does not belong to the client certificate" in r.json()["detail"]


@pytest.mark.parametrize("which,value,message", [
    ("client_cert", "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n", "secrets.client_cert: the certificate could not be read"),
    ("client_key", "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n", "secrets.client_key: the private key could not be read"),
])
def test_ejbca_refuses_a_certificate_or_key_that_does_not_parse(api, world, which, value, message):  # noqa: F811  (the API fixtures)
    node_id, _token, _ = enroll_node(api)
    cert, key = _pair()
    body = _ejbca(node_id, cert, key)
    body["secrets"][which] = value
    r = api("POST", "/1/cbom/sources/items", json=body)
    assert r.status_code == 400 and r.json()["detail"].startswith(message), r.text


# ----------------------------------------------------------------------------- C8: latest collection next to latest test
def test_a_source_serves_its_latest_collection_result(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    src, _run, claim, hdr = _collect_job(api, engine)
    before = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    assert before["last_collect"] is None
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "failure", "error": "WinRM: connection refused"})
    assert r.status_code == 200, r.text
    got = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    last = got["last_collect"]
    assert last["status"] == "failed" and last["at"].endswith("Z") and last["job_id"] == claim["job"]["id"]
    assert last["summary"] == "WinRM: connection refused"
    listed = {s["id"]: s for s in api("GET", "/1/cbom/sources/items").json()["sources"]}
    assert listed[src["id"]]["last_collect"] == last


# ----------------------------------------------------------------------------- C10d: EJBCA profiles that allow PQ
def _pq_names(n: int = 1) -> list[str]:
    """Post-quantum signature names as algid knows them (never written here: algid is the one table)."""
    names = [name for name, row in algid._ALGS.items() if row[0] == "PQ" and algid.resolve(name)
             and algid.resolve(name).primitive == "signature" and not algid.resolve(name).stateful
             and algid.resolve(name).construction == "pure" and algid.resolve(name).parameter_set]
    assert len(names) >= n
    return names[:n]


def test_ejbca_profile_classification_reads_every_allowed_algorithm():
    pq = _pq_names()[0]
    facts = {"provider": "ejbca", "name": "EJBCA profile ENDUSER", "key_type": "RSA", "key_bits": 1024,
             "available_key_algs": ["RSA", "ECDSA", pq.upper()]}
    # stored by a scan node from before the fix (label RSA): a profile that offers a PQ algorithm is not vulnerable
    out = classify("ca_template", "RSA", 1024, None, facts)
    assert out["quantum_vulnerable"] is False
    # the RSA size rule still applies to the RSA keys it still allows, whatever the label
    facts_new = {**facts, "key_type": pq.upper()}
    out = classify("ca_template", pq.upper(), None, None, facts_new)
    assert out["quantum_vulnerable"] is False and "CA_ALLOWS_WEAK_KEY" in out["finding_codes"]
    classical = classify("ca_template", "RSA", 2048, None, {**facts, "key_bits": 2048, "available_key_algs": ["RSA", "ECDSA"]})
    assert classical["quantum_vulnerable"] is True
