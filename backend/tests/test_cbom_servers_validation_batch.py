"""Servers form validation (#148, #149, #154, #156): nothing is silently dropped from a target or never-scan line,
known_hosts is parsed (and a private key refused), an SSH certificate and its key are checked as a pair at save, and
Windows / Active Directory sources refuse settings that are unsafe or that their collectors ignore."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import KNOWN_HOSTS, PASSWORD, api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.utilities.cbom_sources import kinds as K  # noqa: E402
from backend.utilities.cbom_sources import targets as T  # noqa: E402

ITEMS = "/1/cbom/sources/items"


# ----------------------------------------------------------------------------- #148 commas
def test_a_target_line_with_a_comma_is_refused_never_cut():
    with pytest.raises(T.TargetError, match=r"line 1 .*one target per line"):
        T.parse_targets(["10.0.0.1, 10.0.0.2", "10.0.0.3"])
    for sep in (";", "\t"):
        with pytest.raises(T.TargetError, match="one target per line"):
            T.parse_targets([f"10.0.0.1{sep}10.0.0.2"])
    # a CSV header row is still skipped whole, and comments and quotes still go
    assert T.parse_targets(['host,owner', '"10.0.0.5" # db']).normalized == ["10.0.0.5"]


def test_a_never_scan_line_with_commas_keeps_every_entry():
    parsed = T.parse_exclusions(["10.20.0.1, 10.20.0.254", "10.30.0.0/24;10.40.0.1\t10.50.0.1"])
    assert parsed.normalized == ["10.20.0.1", "10.20.0.254", "10.30.0.0/24", "10.40.0.1", "10.50.0.1"]


def test_the_api_refuses_comma_targets_and_keeps_comma_exclusions(api, world):  # noqa: F811 (pytest fixtures)
    node_id, _t, _ = enroll_node(api)
    r = api("POST", ITEMS, json=linux_body("commas", node_id=node_id, targets=["10.0.0.1, 10.0.0.2", "10.0.0.3"]))
    assert r.status_code == 400 and "one target per line" in r.json()["detail"], r.text
    ok = api("POST", ITEMS, json=linux_body("ex", node_id=node_id, targets=["10.20.0.0/24"],
                                            exclusions=["10.20.0.1, 10.20.0.254"]))
    assert ok.status_code == 201, ok.text
    assert ok.json()["source"]["config"]["exclusions"] == ["10.20.0.1", "10.20.0.254"]
    count = api("POST", "/1/cbom/sources/targets/count", json={"targets": ["10.0.0.1, 10.0.0.2"], "exclusions": []})
    assert count.status_code == 200 and count.json()["valid"] is False
    assert "one target per line" in count.json()["error"]


# ----------------------------------------------------------------------------- #149 known_hosts
ECDSA = ("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMj"
         "NuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=")


def test_known_hosts_is_parsed_and_private_keys_refused():
    good = "\n".join([
        "# ssh-keyscan output", KNOWN_HOSTS, f"[10.20.0.2]:2222,app-02.bank.local {ECDSA} root@scan",
        f"|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {ECDSA}", f"@cert-authority *.bank.local {ECDSA}", ""])
    assert K.check_known_hosts(good) == good.replace("\r\n", "\n")
    for bad, why in {
        "hello world": "line 1",
        "10.0.0.1 ssh-ed25519": "line 1",
        "10.0.0.1 ssh-ed25519 not-base64!!": "line 1",
        # the key blob says ecdsa, the line says ed25519
        f"10.0.0.1 ssh-ed25519 {ECDSA.split()[1]}": "line 1",
        f"{KNOWN_HOSTS}\n10.0.0.9 ssh-rsa": "line 2",
    }.items():
        with pytest.raises(ValueError, match=why):
            K.check_known_hosts(bad)
    key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    with pytest.raises(ValueError, match="private key"):
        K.check_known_hosts(key)
    with pytest.raises(ValueError, match="private key"):
        K.check_known_hosts(KNOWN_HOSTS + "\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")


def test_the_api_refuses_bad_known_hosts_for_servers_and_appliances(api, world):  # noqa: F811 (pytest fixtures)
    node_id, _t, _ = enroll_node(api)
    for text in ("hello world", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"):
        body = linux_body("kh", node_id=node_id, targets=["10.20.0.1"], known_hosts=text)
        r = api("POST", ITEMS, json=body)
        assert r.status_code == 400 and "known_hosts" in r.json()["detail"], r.text
        assert "AAAA" not in r.text  # never echoed
    assert api("POST", ITEMS, json=linux_body("kh-ok", node_id=node_id, targets=["10.20.0.1"])).status_code == 201
    appliance = K.KINDS["appliance"].model
    with pytest.raises(ValueError, match="known_hosts"):
        appliance.model_validate({"vendor": "cisco_ios", "targets": ["10.30.0.1"], "credential_type": "password",
                                  "host_key_policy": "pinned", "known_hosts": "hello world"})


# ----------------------------------------------------------------------------- #154 SSH certificate pair
def _ssh_pair(*, valid_for=dt.timedelta(days=1), other_key=False):
    ca = ed25519.Ed25519PrivateKey.generate()
    user = ed25519.Ed25519PrivateKey.generate()
    now = dt.datetime.now(dt.timezone.utc)
    cert = (serialization.SSHCertificateBuilder()
            .public_key(user.public_key()).serial(1).type(serialization.SSHCertificateType.USER).key_id(b"zs")
            .valid_principals([b"zs-cbom"])
            .valid_after(int((now - dt.timedelta(hours=1)).timestamp()))
            .valid_before(int((now + valid_for).timestamp()))
            .sign(ca))
    key = ed25519.Ed25519PrivateKey.generate() if other_key else user
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                            serialization.NoEncryption()).decode()
    return cert.public_bytes().decode(), pem


def _cert_body(node_id, cert, key, name="cert"):
    return {"kind": "linux_servers", "name": name, "node_id": node_id,
            "config": {"targets": ["10.20.0.1"], "credential_type": "ssh_cert", "login_user": "zs-cbom"},
            "secrets": {"ssh_certificate": cert, "private_key": key}}


def test_ssh_certificate_and_key_are_checked_as_a_pair():
    cert, key = _ssh_pair()
    assert K.ssh_pair_problem(cert, key) is None
    assert "could not be read" in K.ssh_pair_problem("garbage", key)
    plain_public = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    assert "not an SSH certificate" in K.ssh_pair_problem(plain_public, key)
    assert "private key could not be read" in K.ssh_pair_problem(cert, "garbage")
    other_cert, other_key = _ssh_pair(other_key=True)
    assert "does not belong" in K.ssh_pair_problem(other_cert, other_key)
    expired, ekey = _ssh_pair(valid_for=-dt.timedelta(minutes=5))
    assert "expired" in K.ssh_pair_problem(expired, ekey)


def test_the_api_checks_the_ssh_pair_on_create_and_on_edit(api, world):  # noqa: F811 (pytest fixtures)
    node_id, _t, _ = enroll_node(api)
    r = api("POST", ITEMS, json=_cert_body(node_id, "garbage", "garbage"))
    assert r.status_code == 400 and "secrets.ssh_certificate" in r.json()["detail"], r.text
    cert, key = _ssh_pair()
    made = api("POST", ITEMS, json=_cert_body(node_id, cert, key, name="cert-ok"))
    assert made.status_code == 201, made.text
    source = made.json()["source"]
    _other_cert, other_key = _ssh_pair()
    r = api("PATCH", f"{ITEMS}/{source['id']}", json={"config": source["config"], "secrets": {"private_key": other_key},
                                                      "expected_version": source["row_version"]})
    assert r.status_code == 400 and "does not belong" in r.json()["detail"], r.text
    assert "PRIVATE KEY" not in r.text


# ----------------------------------------------------------------------------- #156 Windows and AD
def _win(kind="windows_servers", **cfg):
    return {"targets": ["10.20.5.10"], "credential_type": "password", **cfg}


@pytest.mark.parametrize("kind,cfg,why", [
    ("windows_servers", {"port": 80}, "HTTPS"),
    ("windows_servers", {"port": 8080}, "HTTPS"),
    ("windows_servers", {"tier": 2}, "tier"),
    ("windows_servers", {"host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS}, "host_key_policy"),
    ("windows_servers", {"known_hosts": KNOWN_HOSTS}, "known_hosts"),
    ("active_directory", {"port": 389}, "LDAPS"),
    ("active_directory", {"port": 3268}, "LDAPS"),
    ("active_directory", {"port": 5985}, "LDAPS"),
    ("active_directory", {"tier": 2}, "tier"),
])
def test_windows_and_ad_refuse_unsafe_or_ignored_settings(kind, cfg, why):
    model = K.KINDS[kind].model
    problem = None
    try:
        parsed = model.model_validate(_win(**cfg))
        problem = K.credential_target_problem(kind, parsed, {"password": PASSWORD})
    except ValueError as exc:
        problem = str(exc)
    assert problem and why in problem, (kind, cfg, problem)


def test_windows_and_ad_safe_settings_still_save(api, world):  # noqa: F811 (pytest fixtures)
    node_id, _t, _ = enroll_node(api)
    for kind, port, name in (("windows_servers", 5986, "win"), ("active_directory", 636, "ad"),
                             ("active_directory", 3269, "ad-gc")):
        body = {"kind": kind, "name": name, "node_id": node_id, "config": _win(port=port),
                "secrets": {"password": PASSWORD}}
        r = api("POST", ITEMS, json=body)
        assert r.status_code == 201, (kind, port, r.text)
    r = api("POST", ITEMS, json={"kind": "windows_servers", "name": "win80", "node_id": node_id,
                                 "config": _win(port=80), "secrets": {"password": PASSWORD}})
    assert r.status_code == 400 and "HTTPS" in r.json()["detail"], r.text


def test_a_team_never_scan_entry_with_commas_keeps_every_address(api, world):  # noqa: F811 (pytest fixtures)
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    r = api("PATCH", "/1/cbom/sources/settings", json={
        "expected_version": settings["row_version"],
        "network_exclusions": [{"cidr": "10.20.0.1, 10.20.0.254", "reason": "gateways"}]})
    assert r.status_code == 200, r.text
    stored = r.json()["settings"]["network_exclusions"]
    assert [(e["cidr"], e["reason"]) for e in stored] == [("10.20.0.1", "gateways"), ("10.20.0.254", "gateways")]
