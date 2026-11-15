"""#59: Linux sources with ``host_key_policy: host_ca`` and their trusted host-CA public keys (real API harness)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import PASSWORD, api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import kinds  # noqa: E402

ITEMS = "/1/cbom/sources/items"


def _ca_line(comment="host-ca@bank") -> str:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " " + comment


def _host_ca_body(node_id, keys, **cfg):
    body = linux_body(node_id=node_id, targets=["10.20.0.1"], host_key_policy="host_ca", host_ca_keys=keys,
                      known_hosts=None, **cfg)
    return body


def test_a_password_source_with_a_host_ca_saves_and_reaches_the_node(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    ca = _ca_line()
    r = api("POST", ITEMS, json=_host_ca_body(node_id, [ca], window="any"))
    assert r.status_code == 201, r.text
    cfg = r.json()["source"]["config"]
    assert cfg["host_key_policy"] == "host_ca" and cfg["host_ca_keys"] == [ca] and cfg["known_hosts"] is None
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "host-ca-run-1"})
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()
    assert claim["source"]["config"]["host_ca_keys"] == [ca]


@pytest.mark.parametrize("keys,message", [
    ([], "host_ca_keys: paste the public key of at least one host CA"),
    (["not a key"], "host_ca_keys: line 1 is not an SSH public key"),
    (["ssh-ed25519-cert-v01@openssh.com AAAA"], "host_ca_keys: line 1 is a certificate"),
    (["-----BEGIN OPENSSH PRIVATE KEY-----"], "host_ca_keys: line 1 is a private key"),
    (["@cert-authority *.bank.local ssh-ed25519 AAAA"], "host_ca_keys: line 1 is a known_hosts line"),
    ([_ca_line() for _ in range(21)], "host_ca_keys: at most 20 host CAs"),
])
def test_host_ca_keys_are_checked_at_save(api, world, keys, message):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    r = api("POST", ITEMS, json=_host_ca_body(node_id, keys))
    assert r.status_code in (400, 422) and message in r.text, r.text


def test_a_weak_rsa_ca_is_refused():
    weak = rsa.generate_private_key(65537, 1024).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    with pytest.raises(ValueError, match="host_ca_keys: line 1 is an RSA key under 2048 bits"):
        kinds.check_host_ca_keys([weak])


def test_host_ca_keys_are_dropped_for_other_policies_and_kept_out_of_their_dump():
    """Existing sources keep their connection version: the field is in the dump only under host_ca."""
    spec = kinds.KINDS["linux_servers"]
    tofu = spec.model.model_validate({"targets": ["10.20.0.1"], "host_ca_keys": [_ca_line()]})
    assert tofu.host_ca_keys == [] and "host_ca_keys" not in tofu.model_dump(mode="json")
    ca = spec.model.model_validate({"targets": ["10.20.0.1"], "host_key_policy": "host_ca", "host_ca_keys": [_ca_line()]})
    assert "host_ca_keys" in ca.model_dump(mode="json")
    assert "host_ca_keys" in kinds.KINDS["linux_servers"].where_fields  # a new CA list clears a stored password


def test_tofu_still_refuses_a_password_and_host_ca_allows_it():
    spec = kinds.KINDS["linux_servers"]
    tofu = spec.model.model_validate({"targets": ["10.20.0.1"], "credential_type": "password"})
    assert "pinned host keys or a host CA" in kinds.credential_target_problem("linux_servers", tofu, {"password": "x"})
    ca = spec.model.model_validate({"targets": ["10.20.0.1"], "credential_type": "password",
                                    "host_key_policy": "host_ca", "host_ca_keys": [_ca_line()]})
    assert kinds.credential_target_problem("linux_servers", ca, {"password": "x"}) is None


def test_windows_sources_refuse_host_ca():
    with pytest.raises(ValueError, match="host_key_policy"):
        kinds.KINDS["windows_servers"].model.model_validate({"targets": ["10.20.0.1"], "host_key_policy": "host_ca",
                                                             "host_ca_keys": [_ca_line()]})


def test_the_backend_knows_host_key_mismatch():
    assert "host_key_mismatch" in J.TARGET_STATUSES
