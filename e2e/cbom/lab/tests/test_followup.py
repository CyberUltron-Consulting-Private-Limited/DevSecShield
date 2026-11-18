"""Issue #93: IdP JWKS, webhook receiver, kind secrets, Ubuntu Tier-2 file modes. No Docker."""
from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

import labfollow  # noqa: E402
import labk8s  # noqa: E402
import labspec as S  # noqa: E402
import oraclefmt  # noqa: E402

_KEYS = [
    {"kid": "rsa-2048", "kty": "RSA", "alg": "RS256", "bits": 2048},
    {"kid": "ec-p256", "kty": "EC", "alg": "ES256", "bits": 256, "crv": "P-256"},
]


def _jwk_rsa(bits: int = 2048) -> dict:
    n = (1 << (bits - 1)) + 3
    return {"kid": "rsa-2048", "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": labfollow.b64url_uint(n), "e": labfollow.b64url_uint(65537)}


def test_a_served_jwks_that_drops_the_ec_key_disagrees() -> None:
    served = {"keys": [_jwk_rsa()]}
    problems = labfollow.idp_mismatches(_KEYS, served)
    assert any(p.startswith("missing ec-p256") for p in problems)
    assert labfollow.idp_mismatches([_KEYS[0]], served) == []


def test_a_receiver_log_that_drops_a_delivery_is_caught() -> None:
    assert labfollow.receiver_missing(["a", "b"], [{"id": "a"}]) == ["b"]
    assert labfollow.receiver_missing(["a"], [{"id": "a"}, {"id": "b"}]) == []


def test_login_cannot_read_a_root_owned_file_without_other_permission() -> None:
    assert labfollow.login_cannot_read("0600", "root") is True
    assert labfollow.login_cannot_read("0640", "root") is True
    assert labfollow.login_cannot_read("0644", "root") is False
    assert labfollow.login_cannot_read("0600", "zs-cbom") is False


def test_a_swapped_tls_secret_disagrees_and_the_real_one_does_not() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    other = pem + "x"
    expect = {"secrets": [{"name": "rsa-2048-valid", "sha256": hashlib.sha256(pem.encode()).hexdigest()}],
              "configmap": {"name": "leaked-key", "sha256": hashlib.sha256(b"key").hexdigest()},
              "ingress_secret": "rsa-2048-valid", "service_accounts": ["zs-cbom-tier1", "zs-cbom-tier2"]}
    good = {"items": [{"metadata": {"name": "rsa-2048-valid"}, "type": "kubernetes.io/tls",
                       "data": {"tls.crt": base64.b64encode(pem.encode()).decode()}}]}
    bad = {"items": [{"metadata": {"name": "rsa-2048-valid"}, "type": "kubernetes.io/tls",
                      "data": {"tls.crt": base64.b64encode(other.encode()).decode()}}]}
    cm = {"items": [{"metadata": {"name": "leaked-key"}, "data": {"app.key": "key"}}]}
    ing = {"items": [{"metadata": {"name": "web"}, "spec": {"tls": [{"secretName": "rsa-2048-valid"}]}}]}
    sas = {"items": [{"metadata": {"name": "zs-cbom-tier1"}}, {"metadata": {"name": "zs-cbom-tier2"}}]}
    assert labfollow.k8s_mismatches(expect, good, cm, ing, sas) == []
    assert "rsa-2048-valid tls.crt" in labfollow.k8s_mismatches(expect, bad, cm, ing, sas)


def test_manifests_carry_the_four_secrets_the_configmap_and_both_accounts() -> None:
    expect = {"secrets": [{"name": n} for n in ("rsa-2048-valid", "ec-p256-valid", "rsa-2048-expired", "rsa-1024")],
              "configmap": {"name": "leaked-key"}, "ingress_secret": "rsa-2048-valid",
              "service_accounts": ["zs-cbom-tier1", "zs-cbom-tier2"]}
    crt = {n: "CERT" for n in ("rsa-2048-valid", "ec-p256-valid", "rsa-2048-expired", "rsa-1024")}
    key = {n: "KEY" for n in crt}
    doc = labk8s.manifests(expect, crt, key, "PRIVATE")
    kinds = {}
    for item in doc["items"]:
        kinds.setdefault(item["kind"], []).append(item["metadata"]["name"])
    assert kinds["Secret"] == ["rsa-2048-valid", "ec-p256-valid", "rsa-2048-expired", "rsa-1024"]
    assert all(item["type"] == "kubernetes.io/tls" for item in doc["items"] if item["kind"] == "Secret")
    assert "PRIVATE" in next(i for i in doc["items"] if i["kind"] == "ConfigMap")["data"]["app.key"]
    assert kinds["ServiceAccount"] == ["zs-cbom-tier1", "zs-cbom-tier2"]
    ingress = next(i for i in doc["items"] if i["kind"] == "Ingress")
    assert ingress["spec"]["tls"][0]["secretName"] == "rsa-2048-valid"


def test_idp_oracle_ids_are_the_ledger_pins() -> None:
    facts = {"target": "idp", "kind": "idp", "address": "10.231.0.42", "port": 443, "provenance": {},
             "expect": {"issuer": "https://idp.lab", "jwks_uri": "https://idp.lab/jwks", "keys": _KEYS}}
    assets, _ = oraclefmt.assets_for(facts, "2026-11-15T00:00:00Z")
    assert [a["oracle_id"] for a in assets] == ["idp/key/rsa-2048", "idp/key/ec-p256"]
    receiver = {"target": "receiver", "kind": "receiver", "address": "10.231.0.43", "port": 8080,
                "provenance": {}, "expect": {}}
    assert oraclefmt.assets_for(receiver, "2026-11-15T00:00:00Z")[0] == []


def test_catalogue_addresses_stay_unique() -> None:
    assert S.validate_catalogue() == []


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_jwks_bit_length_matches_the_spki() -> None:
    # A private directory: the self-hosted runners share /tmp, so a fixed path collides.
    with tempfile.TemporaryDirectory(prefix="cb02-followup-spki-") as workdir:
        key = Path(workdir) / "rsa.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(key)], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
    numbers = labfollow.public_numbers(der)
    jwk = labfollow.jwk_from("rsa-2048", "RS256", "sig", numbers)
    assert numbers["bits"] == 2048
    assert labfollow.jwk_bits(jwk) == 2048
    assert labfollow.idp_mismatches(
        [{"kid": "rsa-2048", "kty": "RSA", "alg": "RS256", "bits": 2048}], {"keys": [jwk]}) == []
